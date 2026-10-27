import assert from "node:assert/strict";
import test from "node:test";
import { canonicalIdempotencyKey, serializeIkCommand, type IssueCredentialCommand } from "../src/command-schema";
import { CredentialBuilder, computeCredentialLeaf, computeOneLeafRoot } from "../src/credential-builder";
import { createPoseidon2 } from "../src/field";
import { derivePersonDid } from "../src/person-did";
import { IdentityAnchorClient, anchorCalldataDigest, type IdentityAnchorReadPort } from "../src/identity-anchor-client";
import {
  InMemoryProviderDecisionStore, ProviderBackedDecisionPort, attestationEvidenceDigest,
} from "../src/provider-decision-port";
import { SchemaRestrictedSigner, type AnchorMutation, type IkSigningPort } from "../src/signer";
import { GapIdentityKeeperV2Worker, InMemoryWorkerStateStore, type IkPolicyReadPort } from "../src/worker";
import {
  APPLICANT_ID, LINK_A, NOW, PERSON_DID_KEY,
  createProviderKey, decisionSlots, liveFrom, policyFor, signAttestation, storedFrom,
} from "./provider-fixture";

const anchor = `0x${"11".repeat(20)}` as const;
const regimeHash = `0x${"22".repeat(32)}` as const;
const ikId = `0x${"04".padStart(64, "0")}` as const;
const salt = `0x${"05".padStart(64, "0")}` as const;
const wallet = `0x${"33".repeat(20)}` as const;
const signerAddress = `0x${"44".repeat(20)}` as const;
const txHash = `0x${"55".repeat(32)}` as const;
// The IK subject id and the onboarding platform's customer-link id are distinct identifiers;
// the case directory is what joins them.
const SUBJECT = "9c8f1a2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const EXPIRES = NOW + 3_000n;

const key = createProviderKey();
const did = derivePersonDid({
  personDidKey: PERSON_DID_KEY, environment: "sandbox", accountLinkId: LINK_A,
});

class FakeSigningPort implements IkSigningPort {
  readonly address = signerAddress;
  readonly sent: AnchorMutation[] = [];
  async sendCredentialMutation(mutation: AnchorMutation) { this.sent.push(mutation); return txHash; }
}

async function buildCommand(attributes: readonly [bigint, bigint], digest: `0x${string}`) {
  const hasher = await createPoseidon2();
  const credential = new CredentialBuilder(hasher).buildIdentityCredentialWithAttributes(
    { chainId: 84532, anchor, regimeHash, did, ikId, privateSalt: salt, expiresAt: EXPIRES },
    NOW,
    attributes,
  );
  const spendingRoot = computeOneLeafRoot(
    hasher, hasher.hash2(BigInt(wallet), 0n), Number(BigInt(wallet) & 0xffn), 8,
  );
  const draft: IssueCredentialCommand = {
    schemaVersion: 1, slot: "IDENTITY", action: "ISSUE", chainId: 84532, anchor, regimeHash,
    activeDID: did, ikId, subjectId: SUBJECT, wallet,
    sourceDecisionRevision: 1n, credentialRevision: 1n,
    sourceDecisionDigest: digest,
    calldataDigest: anchorCalldataDigest({
      functionName: "issueCredential", anchor, regimeHash, did,
      commitment: credential.commitment, expiresAt: EXPIRES, ikId,
    }),
    idempotencyKey: "", attributes, privateSalt: salt, expiresAt: EXPIRES,
    commitment: credential.commitment,
    expectedSpendingRoot: `0x${spendingRoot.toString(16).padStart(64, "0")}`,
  };
  return { hasher, spendingRoot, command: { ...draft, idempotencyKey: canonicalIdempotencyKey(draft) } };
}

async function harness(options: { readonly seedStore: boolean }) {
  const envelope = signAttestation(key, decisionSlots({ expiresAt: String(NOW + 3_600n) }));
  const store = new InMemoryProviderDecisionStore();
  if (options.seedStore) await store.write(LINK_A, storedFrom(envelope));
  const decisions = new ProviderBackedDecisionPort({
    policy: policyFor(key),
    directory: {
      async lookup() {
        return { subjectId: SUBJECT, accountLinkId: LINK_A, applicantId: APPLICANT_ID, wallet };
      },
    },
    store,
    live: { async readStatus() { return liveFrom(envelope); } },
    personDidKey: PERSON_DID_KEY,
    now: () => NOW,
  });
  const built = await buildCommand([826n, 0n, 826n, 0n], attestationEvidenceDigest(envelope));
  const signingPort = new FakeSigningPort();
  const empty = {
    commitment: `0x${"00".repeat(32)}` as const, issuerIKId: ikId,
    issuedAt: 0n, expiresAt: 0n, revoked: false, treeIndex: 3,
  };
  const reader: IdentityAnchorReadPort = {
    async simulateCredentialMutation() {},
    async waitForCanonicalReceipt(transactionHash) {
      return {
        transactionHash, blockNumber: 100n, blockHash: `0x${"77".repeat(32)}` as const,
        canonical: true, status: "SUCCESS" as const, from: signerAddress, to: anchor,
        calldataDigest: built.command.calldataDigest,
      };
    },
    async getCredential() {
      return { ...empty, commitment: built.command.commitment, issuedAt: 10n, expiresAt: EXPIRES };
    },
  };
  const policy: IkPolicyReadPort = {
    async readDid() {
      return {
        exists: true,
        privateSaltCommitment: `0x${built.hasher.hash2(BigInt(salt), 0n).toString(16).padStart(64, "0")}` as const,
        spendingKeyRoot: built.command.expectedSpendingRoot,
        governanceKeys: [wallet],
      };
    },
    async isIkActiveAndAuthorized() { return true; },
    async readCredential() { return empty; },
  };
  const worker = new GapIdentityKeeperV2Worker(
    "IDENTITY", built.hasher, decisions, policy,
    new IdentityAnchorClient(reader, new SchemaRestrictedSigner(signingPort, anchor, ikId), 2),
    new InMemoryWorkerStateStore(), signerAddress, () => NOW,
  );
  return { worker, built, signingPort, envelope };
}

test("a GB person with a verified decision issues a credential carrying country 826", async () => {
  const fixture = await harness({ seedStore: true });
  const result = await fixture.worker.handle(serializeIkCommand(fixture.built.command));
  assert.equal(result.transactionHash, txHash);
  assert.equal(fixture.signingPort.sent.length, 1);
  assert.deepEqual(fixture.built.command.attributes, [826n, 0n, 826n, 0n]);
  // The leaf layout is untouched: only the attribute VALUES changed.
  assert.equal(
    computeCredentialLeaf(fixture.built.hasher, {
      chainId: 84532, anchor, regimeHash, did, ikId,
      attributes: [826n, 0n, 826n, 0n], privateSalt: salt, expiresAt: EXPIRES,
    }),
    fixture.built.command.commitment,
  );
});

test("with no verified provider decision the worker never submits anything", async () => {
  const fixture = await harness({ seedStore: false });
  await assert.rejects(
    fixture.worker.handle(serializeIkCommand(fixture.built.command)),
    /identity issuance requires a verified provider decision/,
  );
  assert.equal(fixture.signingPort.sent.length, 0);
});

test("hand-picked attributes are refused even when the command is internally consistent", async () => {
  const fixture = await harness({ seedStore: true });
  // A well-formed command claiming US residency for a GB person: the commitment
  // and calldata digest agree with each other, and only the provenance check
  // catches it.
  const forged = await buildCommand([840n, 0n, 840n, 0n], attestationEvidenceDigest(fixture.envelope));
  await assert.rejects(
    fixture.worker.handle(serializeIkCommand(forged.command)),
    /credential attributes do not match the verified provider decision/,
  );
  assert.equal(fixture.signingPort.sent.length, 0);
});
