import {
  SHA256_HEX_PATTERN,
  decodeSlotArray,
  epochSeconds,
  expectIsoUtc,
  expectString,
  expectUint64,
  openSignedAttestation,
  parseSignedEnvelope,
  type EnvelopeShape,
} from "./signed-attestation";

/**
 * `ProviderIdentityAttestation`: the signed decision envelope the Identity
 * Keeper verifies ITSELF.
 *
 * It exists because the adapter's `IdentityDecision` is *derived locally* by the
 * adapter and carries no provider signature, no country, and no sanctions
 * result. Trusting it would make the IK trust its own caller. This module
 * re-verifies Ed25519 over the exact received payload bytes, so the webhook copy
 * and the live-read copy are comparable byte-for-byte.
 *
 * SCOPE: identity facts only, residency country, citizenship country and sanctions
 * screening. Residency and citizenship are SEPARATE slots and separate attributes: where a
 * person lives is not what they are a national of, and a sanctions programme may key on
 * either. The
 * KYC provider does not attest suitability and must never be read as if it did;
 * `./suitability-attestation.ts` is that separate authority,
 * built on the same `signed-attestation` primitives as this file.
 */
// V2 adds citizenshipCountryAlpha3 at slot 13, shifting slots 13..18 up by one. The profile
// string is bumped with the shape so a V1 payload is REFUSED on profile mismatch rather than
// silently decoded against the wrong positions.
export const ATTESTATION_PROFILE = "DSI_PROVIDER_IDENTITY_ATTESTATION_V2";
export const ATTESTATION_SLOTS = 20;
export const DEFAULT_SCREENING_FRESHNESS_SECONDS = 24n * 60n * 60n;
export const DEFAULT_OBSERVED_SKEW_SECONDS = 60n;

export interface ProviderAttestationEnvelope {
  readonly profile: string;
  readonly keyId: string;
  readonly payload: string;
  readonly signature: string;
}

export interface ProviderDecision {
  readonly profile: typeof ATTESTATION_PROFILE;
  readonly provider: "kyc-provider";
  readonly environment: "sandbox";
  readonly clientId: string;
  readonly levelName: string;
  readonly levelPolicyRevision: 1;
  readonly reviewedConfigurationSha256: `0x${string}`;
  readonly subject: string;
  readonly applicantId: string;
  readonly decisionRevision: bigint;
  readonly reviewAnswer: "GREEN" | "RED";
  readonly reviewRejectType: "FINAL" | "RETRY" | null;
  readonly residencyCountryAlpha3: string;
  readonly citizenshipCountryAlpha3: string;
  readonly countryTableRevision: number;
  readonly screeningResult: "CLEAR" | "HIT";
  readonly screenedAt: string;
  readonly observedAt: string;
  readonly expiresAt: bigint;
  readonly nonce: `0x${string}`;
}

export interface AttestationPolicy {
  readonly clientId: string;
  readonly levelName: string;
  readonly environment: "sandbox";
  readonly levelPolicyRevision: 1;
  readonly reviewedConfigurationSha256: `0x${string}`;
  readonly countryTableRevision: number;
  /** keyId -> `0x`-prefixed 32-byte Ed25519 public key. Unknown keyId => refuse. */
  readonly publicKeys: Readonly<Record<string, string>>;
}

export interface AttestationVerifyContext {
  readonly policy: AttestationPolicy;
  /** The accountLinkId this issuance is for. `decision.subject` must equal it. */
  readonly expectedSubject: string;
  readonly now: bigint;
  /** Webhook eventId (`0x` + sha256(rawBody)) the attestation must be bound to. */
  readonly expectedNonce?: string;
  readonly screeningFreshnessSeconds?: bigint;
  readonly observedSkewSeconds?: bigint;
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const APPLICANT_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The envelope shape every copy of this attestation must present. */
const PROVIDER_ENVELOPE: EnvelopeShape = {
  profile: ATTESTATION_PROFILE,
  noun: "provider attestation",
};

export function parseAttestationEnvelope(value: unknown): ProviderAttestationEnvelope {
  return parseSignedEnvelope(value, PROVIDER_ENVELOPE);
}

/** Decode the canonical 19-slot positional payload. Slot order is normative. */
export function decodeAttestationPayload(payloadBytes: Buffer): ProviderDecision {
  return decodeProviderSlots(decodeSlotArray({
    payload: payloadBytes,
    profile: ATTESTATION_PROFILE,
    slotCount: ATTESTATION_SLOTS,
  }));
}

function decodeProviderSlots(slots: readonly unknown[]): ProviderDecision {
  if (slots[1] !== "kyc-provider") throw new Error("attestation provider is not kyc-provider");
  if (slots[2] !== "sandbox") throw new Error("attestation environment is not sandbox");
  const reviewedConfigurationSha256 = expectString(slots, 6, "reviewedConfigurationSha256");
  if (!SHA256_HEX_PATTERN.test(reviewedConfigurationSha256)) {
    throw new Error("reviewedConfigurationSha256 must be lowercase 0x sha-256 hex");
  }
  const subject = expectString(slots, 7, "attestation subject");
  if (!UUID_V4.test(subject)) throw new Error("attestation subject must be canonical lowercase UUIDv4");
  const applicantId = expectString(slots, 8, "applicantId");
  if (!APPLICANT_ID.test(applicantId)) throw new Error("applicantId is malformed");
  const decisionRevision = expectUint64(slots, 9, "decisionRevision");
  if (decisionRevision < 1n) throw new Error("decisionRevision must be >= 1");
  const reviewAnswer = slots[10];
  if (reviewAnswer !== "GREEN" && reviewAnswer !== "RED") throw new Error("reviewAnswer is not GREEN or RED");
  const reviewRejectType = slots[11];
  if (reviewRejectType !== null && reviewRejectType !== "FINAL" && reviewRejectType !== "RETRY") {
    throw new Error("reviewRejectType is not FINAL, RETRY, or null");
  }
  if ((reviewAnswer === "GREEN") !== (reviewRejectType === null)) {
    throw new Error("reviewRejectType must be null exactly when reviewAnswer is GREEN");
  }
  const residencyCountryAlpha3 = expectString(slots, 12, "residencyCountryAlpha3");
  if (!/^[A-Z]{3}$/.test(residencyCountryAlpha3)) throw new Error("residencyCountryAlpha3 must be 3 uppercase letters");
  const citizenshipCountryAlpha3 = expectString(slots, 13, "citizenshipCountryAlpha3");
  if (!/^[A-Z]{3}$/.test(citizenshipCountryAlpha3)) {
    throw new Error("citizenshipCountryAlpha3 must be 3 uppercase letters");
  }
  const countryTableRevision = expectUint64(slots, 14, "countryTableRevision");
  const screeningResult = slots[15];
  if (screeningResult !== "CLEAR" && screeningResult !== "HIT") {
    throw new Error("screeningResult must be CLEAR or HIT");
  }
  const screenedAt = expectIsoUtc(slots, 16, "screenedAt");
  const observedAt = expectIsoUtc(slots, 17, "observedAt");
  const expiresAt = expectUint64(slots, 18, "attestation expiresAt");
  if (expiresAt <= epochSeconds(observedAt)) throw new Error("attestation expiresAt must be after observedAt");
  const nonce = expectString(slots, 19, "attestation nonce");
  if (!SHA256_HEX_PATTERN.test(nonce)) throw new Error("attestation nonce must be lowercase 0x sha-256 hex");
  return {
    profile: ATTESTATION_PROFILE,
    provider: "kyc-provider",
    environment: "sandbox",
    clientId: expectString(slots, 3, "clientId"),
    levelName: expectString(slots, 4, "levelName"),
    levelPolicyRevision: Number(expectUint64(slots, 5, "levelPolicyRevision")) as 1,
    reviewedConfigurationSha256: reviewedConfigurationSha256 as `0x${string}`,
    subject,
    applicantId,
    decisionRevision,
    reviewAnswer,
    reviewRejectType,
    residencyCountryAlpha3,
    citizenshipCountryAlpha3,
    countryTableRevision: Number(countryTableRevision),
    screeningResult,
    screenedAt,
    observedAt,
    expiresAt,
    nonce: nonce as `0x${string}`,
  };
}

export interface VerifiedAttestation {
  readonly envelope: ProviderAttestationEnvelope;
  readonly decision: ProviderDecision;
}

/**
 * Full §1.5 verification, run by the IK over the bytes it received.
 * Every failure is a refusal: there is no downgrade path.
 */
export function verifyProviderAttestation(
  input: unknown,
  context: AttestationVerifyContext,
): VerifiedAttestation {
  const opened = openSignedAttestation(input, {
    ...PROVIDER_ENVELOPE,
    slotCount: ATTESTATION_SLOTS,
    publicKeys: context.policy.publicKeys,
  });
  const envelope = opened.envelope as ProviderAttestationEnvelope;
  const decision = decodeProviderSlots(opened.slots);
  const policy = context.policy;
  if (decision.clientId !== policy.clientId
    || decision.levelName !== policy.levelName
    || decision.environment !== policy.environment
    || decision.levelPolicyRevision !== policy.levelPolicyRevision
    || decision.reviewedConfigurationSha256 !== policy.reviewedConfigurationSha256) {
    throw new Error("attestation level/client context is not the reviewed configuration");
  }
  if (decision.countryTableRevision !== policy.countryTableRevision) {
    throw new Error("attestation country table revision does not match the reviewed table");
  }
  if (decision.subject !== context.expectedSubject) {
    throw new Error("attestation subject does not match the account link id");
  }
  if (context.expectedNonce !== undefined && decision.nonce !== context.expectedNonce) {
    throw new Error("attestation nonce is not bound to the recorded webhook delivery");
  }
  const skew = context.observedSkewSeconds ?? DEFAULT_OBSERVED_SKEW_SECONDS;
  const freshness = context.screeningFreshnessSeconds ?? DEFAULT_SCREENING_FRESHNESS_SECONDS;
  if (epochSeconds(decision.observedAt) > context.now + skew) {
    throw new Error("attestation was observed in the future");
  }
  if (context.now >= decision.expiresAt) throw new Error("provider decision has expired");
  if (context.now - epochSeconds(decision.screenedAt) > freshness) {
    throw new Error("sanctions screening is stale");
  }
  return { envelope, decision };
}
