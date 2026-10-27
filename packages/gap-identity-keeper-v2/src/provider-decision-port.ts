import { createHash } from "node:crypto";
import {
  assertIssuableProviderState,
  deriveIdentityAttributes,
  type IdentityAttributes,
  type ProviderStatusView,
} from "./attribute-derivation";
import { COUNTRY_TABLE_REVISION } from "./country-table";
import { derivePersonDid, isCanonicalSubjectId } from "./person-did";
import {
  ATTESTATION_PROFILE,
  verifyProviderAttestation,
  type AttestationPolicy,
  type ProviderAttestationEnvelope,
  type VerifiedAttestation,
} from "./provider-attestation";
import type { Address, Bytes32, CredentialSlot, SourceDecisionSnapshot } from "./types";
import type { AuthoritativeDecisionPort } from "./worker";

/** Channel A: the durable decision of record, established by a signed webhook. */
export interface StoredProviderDecision {
  readonly keyId: string;
  readonly payload: string;
  readonly signature: string;
  /** `0x` + sha256(rawWebhookBody): the attestation nonce must equal this. */
  readonly webhookEventId: string;
  /** The webhook's own state fields, gated alongside the live read. */
  readonly webhookStatus: ProviderStatusView;
}

export interface ProviderDecisionStore {
  read(accountLinkId: string): Promise<StoredProviderDecision | undefined>;
  write(accountLinkId: string, record: StoredProviderDecision): Promise<void>;
}

export class InMemoryProviderDecisionStore implements ProviderDecisionStore {
  private readonly rows = new Map<string, StoredProviderDecision>();
  async read(accountLinkId: string) { return this.rows.get(accountLinkId); }
  async write(accountLinkId: string, record: StoredProviderDecision) {
    this.rows.set(accountLinkId, record);
  }
}

/** Channel B: a fresh live read. A cached response is not acceptable. */
export interface LiveProviderStatus extends ProviderStatusView {
  readonly applicantId: string;
  readonly externalUserId: string;
  readonly providerAttestation?: unknown;
}

export interface LiveProviderStatusPort {
  readStatus(applicantId: string): Promise<LiveProviderStatus>;
}

export interface IdentityCaseBinding {
  readonly subjectId: string;
  /** The onboarding platform's customer-link id == the provider applicant externalUserId. */
  readonly accountLinkId: string;
  readonly applicantId: string;
  /**
   * The subject's bound wallet, CARRIED when one exists. A runtime holder's
   * identity credential mints during provisioning, before their first
   * enrollment: the leaf names no wallet, so the case resolves without one.
   * Consumers that compare wallets (the compliance-package path) refuse an
   * absent value: `sameHex(undefined, addr)` is false, never a pass.
   */
  readonly wallet?: Address;
}

export interface IdentityCaseDirectory {
  lookup(subjectId: string): Promise<IdentityCaseBinding | undefined>;
}

export interface ProviderBackedDecisionOptions {
  readonly policy: AttestationPolicy;
  readonly directory: IdentityCaseDirectory;
  readonly store: ProviderDecisionStore;
  readonly live: LiveProviderStatusPort;
  /** 32-byte IK-held secret for per-person DID derivation. */
  readonly personDidKey: Uint8Array;
  readonly now?: () => bigint;
  /** TA-gated fund decisions keep their existing source. */
  readonly fundDelegate?: AuthoritativeDecisionPort;
}

/** Deterministic digest of the signed envelope, usable as the source-decision digest. */
export function attestationEvidenceDigest(envelope: ProviderAttestationEnvelope): Bytes32 {
  const canonical = JSON.stringify([
    envelope.profile, envelope.keyId, envelope.payload, envelope.signature,
  ]);
  return `0x${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/**
 * The load-bearing decision port.
 *
 * `readDecision` is on the path of every `authorize`, so a refusal here means
 * nothing is ever submitted on chain. It refuses when: no durable decision
 * exists, either channel fails Ed25519/format/freshness verification, the
 * decision's subject is not this case's accountLinkId, the two channels
 * equivocate, the live read is unavailable or omits the attestation, either
 * channel's provider state is not APPROVED, or the attributes cannot be derived.
 */
export class ProviderBackedDecisionPort implements AuthoritativeDecisionPort {
  private readonly now: () => bigint;

  constructor(private readonly options: ProviderBackedDecisionOptions) {
    if (options.policy.countryTableRevision !== COUNTRY_TABLE_REVISION) {
      throw new Error("pinned country table revision differs from the reviewed table");
    }
    this.now = options.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
  }

  async readDecision(
    slot: CredentialSlot,
    subjectId: string,
    token?: `0x${string}`,
  ): Promise<SourceDecisionSnapshot> {
    if (slot === "FUND") {
      if (!this.options.fundDelegate) throw new Error("no fund decision source is configured");
      return this.options.fundDelegate.readDecision(slot, subjectId, token);
    }
    const binding = await this.options.directory.lookup(subjectId);
    if (!binding || binding.subjectId !== subjectId) {
      throw new Error("no identity case is known for this subject");
    }
    if (!isCanonicalSubjectId(binding.accountLinkId)) {
      throw new Error("accountLinkId must be a canonical lowercase UUIDv4");
    }
    const stored = await this.options.store.read(binding.accountLinkId);
    // Core requirement: no verified provider decision => no credential.
    if (!stored) throw new Error("identity issuance requires a verified provider decision");
    const durable = this.verify(
      { profile: ATTESTATION_PROFILE, keyId: stored.keyId, payload: stored.payload, signature: stored.signature },
      binding.accountLinkId,
      stored.webhookEventId,
    );
    if (durable.decision.applicantId !== binding.applicantId) {
      throw new Error("stored decision belongs to a different applicant");
    }
    assertIssuableProviderState(stored.webhookStatus, "webhook");

    const live = await this.readLive(binding.applicantId);
    if (live.applicantId !== binding.applicantId
      || live.externalUserId !== binding.accountLinkId) {
      throw new Error("live provider status is bound to a different applicant/subject");
    }
    if (live.providerAttestation === undefined || live.providerAttestation === null) {
      throw new Error("live provider status carries no provider attestation");
    }
    const fresh = this.verify(live.providerAttestation, binding.accountLinkId);
    if (fresh.decision.applicantId !== binding.applicantId) {
      throw new Error("live decision belongs to a different applicant");
    }
    assertIssuableProviderState(live, "live");

    const record = this.reconcile(durable, fresh);
    if (record !== durable) {
      await this.options.store.write(binding.accountLinkId, {
        keyId: record.envelope.keyId,
        payload: record.envelope.payload,
        signature: record.envelope.signature,
        webhookEventId: record.decision.nonce,
        webhookStatus: stored.webhookStatus,
      });
    }
    const attributes: IdentityAttributes = deriveIdentityAttributes(
      record.decision,
      this.options.policy.countryTableRevision,
    );
    return {
      revision: record.decision.decisionRevision,
      evidenceDigest: attestationEvidenceDigest(record.envelope),
      approved: true,
      subjectId,
      ...(binding.wallet ? { wallet: binding.wallet } : {}),
      did: derivePersonDid({
        personDidKey: this.options.personDidKey,
        environment: "sandbox",
        accountLinkId: binding.accountLinkId,
      }),
      expiresAt: record.decision.expiresAt,
      attributes,
    };
  }

  private verify(input: unknown, expectedSubject: string, expectedNonce?: string): VerifiedAttestation {
    return verifyProviderAttestation(input, {
      policy: this.options.policy,
      expectedSubject,
      now: this.now(),
      ...(expectedNonce === undefined ? {} : { expectedNonce }),
    });
  }

  /**
   * Channel B must never be behind channel A. Equal revisions must be the same
   * bytes; anything else is equivocation between the two transports.
   */
  private reconcile(durable: VerifiedAttestation, fresh: VerifiedAttestation): VerifiedAttestation {
    if (fresh.decision.decisionRevision < durable.decision.decisionRevision) {
      throw new Error("live provider decision is behind the stored decision");
    }
    if (fresh.decision.decisionRevision === durable.decision.decisionRevision) {
      if (fresh.envelope.payload !== durable.envelope.payload
        || fresh.envelope.signature !== durable.envelope.signature) {
        throw new Error("provider decision equivocates between webhook and live read");
      }
      return durable;
    }
    return fresh;
  }

  private async readLive(applicantId: string): Promise<LiveProviderStatus> {
    let live: LiveProviderStatus;
    try {
      live = await this.options.live.readStatus(applicantId);
    } catch (error) {
      // Deliberately stricter than the reconciler's hold path, where a fetch
      // failure is swallowed. Issuance fails closed.
      throw new Error(`live provider status re-read is unavailable: ${(error as Error).message}`);
    }
    if (!live || typeof live !== "object") throw new Error("live provider status is unusable");
    return live;
  }
}
