import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalIdempotencyKey, parseIkCommand, serializeIkCommand, type IssueCredentialCommand,
} from "../src/command-schema";
import { computeCredentialLeaf, computeOneLeafRoot } from "../src/credential-builder";
import { createPoseidon2 } from "../src/field";
import { IdentityAnchorClient, ReorgDetectedError, anchorCalldataDigest, type IdentityAnchorReadPort } from "../src/identity-anchor-client";
import { SchemaRestrictedSigner, type AnchorMutation, type IkSigningPort } from "../src/signer";
import { GapIdentityKeeperV2Worker, InMemoryWorkerStateStore, type IkPolicyReadPort } from "../src/worker";

const anchor = `0x${"11".repeat(20)}` as const;
const regimeHash = `0x${"22".repeat(32)}` as const;
const did = `0x${"03".padStart(64, "0")}` as const;
const ikId = `0x${"04".padStart(64, "0")}` as const;
const salt = `0x${"05".padStart(64, "0")}` as const;
const wallet = `0x${"33".repeat(20)}` as const;
const subjectId = "123e4567-e89b-42d3-a456-426614174000";
const signerAddress = `0x${"44".repeat(20)}` as const;
const txHash = `0x${"55".repeat(32)}` as const;

async function command(): Promise<{ command: IssueCredentialCommand; spendingRoot: `0x${string}` }> {
  const hasher = await createPoseidon2();
  const expiresAt = 1_800_000_000n;
  const commitment = computeCredentialLeaf(hasher, {
    chainId: 84532, anchor, regimeHash, did, ikId, attributes: [1n, 1n, 0n, 0n], privateSalt: salt, expiresAt,
  });
  const root = computeOneLeafRoot(hasher, hasher.hash2(BigInt(wallet), 0n), Number(BigInt(wallet) & 0xffn), 8);
  const calldataDigest = anchorCalldataDigest({
    functionName: "issueCredential", anchor, regimeHash, did, commitment, expiresAt, ikId,
  });
  const draft: IssueCredentialCommand = {
    schemaVersion: 1, slot: "IDENTITY", action: "ISSUE", chainId: 84532, anchor, regimeHash,
    activeDID: did, ikId, subjectId, wallet, sourceDecisionRevision: 1n, credentialRevision: 1n,
    sourceDecisionDigest: `0x${"66".repeat(32)}`, calldataDigest, idempotencyKey: "", attributes: [1n, 1n, 0n, 0n],
    privateSalt: salt, expiresAt, commitment, expectedSpendingRoot: `0x${root.toString(16).padStart(64, "0")}`,
  };
  return { command: { ...draft, idempotencyKey: canonicalIdempotencyKey(draft) }, spendingRoot: draft.expectedSpendingRoot };
}

test("command schema freezes canonical decimal revisions, keys, attributes, and privacy surface", async () => {
  const built = await command();
  const json = serializeIkCommand(built.command);
  assert.deepEqual(parseIkCommand(json), built.command);
  assert.throws(() => parseIkCommand({ ...json, credentialRevision: "01" }), /canonical decimal/);
  // IDENTITY attributes are provider-derived, so the pair is no longer frozen, 
  // but it must still be canonical decimal, and the FUND slot stays [1,1].
  assert.deepEqual((parseIkCommand({ ...json, attributes: ["826", "0", "826", "0"] }) as IssueCredentialCommand).attributes, [826n, 0n, 826n, 0n]);
  assert.throws(() => parseIkCommand({ ...json, attributes: ["01", "0", "826", "0"] }), /canonical decimal/);
  assert.throws(() => parseIkCommand({ ...json, attributes: ["1"] }), /four values/);
  assert.throws(
    () => parseIkCommand({ ...json, slot: "FUND", token: `0x${"77".repeat(20)}`, attributes: ["826", "0", "826", "0"] }),
    /fund issuer attributes must be exactly/,
  );
  assert.throws(() => parseIkCommand({ ...json, applicantId: "forbidden" }), /unexpected IK command key/);
  assert.throws(() => parseIkCommand({ ...json, idempotencyKey: "arbitrary" }), /noncanonical/);
});

class FakeSigningPort implements IkSigningPort {
  readonly address = signerAddress;
  readonly sent: AnchorMutation[] = [];
  async sendCredentialMutation(mutation: AnchorMutation) { this.sent.push(mutation); return txHash; }
}

async function setup(canonical = true) {
  const built = await command();
  const hasher = await createPoseidon2();
  const signingPort = new FakeSigningPort();
  const signer = new SchemaRestrictedSigner(signingPort, anchor, ikId);
  const emptyCredential = { commitment: `0x${"00".repeat(32)}` as const, issuerIKId: ikId, issuedAt: 0n, expiresAt: 0n, revoked: false, treeIndex: 3 };
  const reader: IdentityAnchorReadPort = {
    async simulateCredentialMutation() {},
    async waitForCanonicalReceipt(transactionHash) {
      return {
        transactionHash,
        blockNumber: 100n,
        blockHash: `0x${"77".repeat(32)}` as const,
        canonical,
        status: "SUCCESS" as const,
        from: signerAddress,
        to: anchor,
        calldataDigest: built.command.calldataDigest,
      };
    },
    async getCredential() { return { ...emptyCredential, commitment: built.command.commitment, issuedAt: 10n, expiresAt: built.command.expiresAt, revoked: false }; },
  };
  const policy: IkPolicyReadPort = {
    async readDid() { return { exists: true, privateSaltCommitment: `0x${hasher.hash2(BigInt(salt), 0n).toString(16).padStart(64, "0")}` as const, spendingKeyRoot: built.spendingRoot, governanceKeys: [wallet] }; },
    async isIkActiveAndAuthorized() { return true; },
    async readCredential() { return emptyCredential; },
  };
  const decisions = {
    async readDecision() {
      return {
        revision: 1n, evidenceDigest: built.command.sourceDecisionDigest, approved: true,
        subjectId, wallet, did, expiresAt: built.command.expiresAt,
        attributes: [1n, 1n, 0n, 0n] as const,
      };
    },
  };
  const state = new InMemoryWorkerStateStore();
  const client = new IdentityAnchorClient(reader, signer, 2);
  const worker = new GapIdentityKeeperV2Worker("IDENTITY", hasher, decisions, policy, client, state, signerAddress, () => 1_799_999_000n);
  return { built, worker, state, signingPort, signer, policy, decisions, client, hasher };
}

test("IK worker rereads decision/DID/route, recomputes the leaf, submits once, and confirms readback", async () => {
  const fixture = await setup();
  const json = serializeIkCommand(fixture.built.command);
  const first = await fixture.worker.handle(json);
  const duplicate = await fixture.worker.handle(json);
  assert.equal(first.transactionHash, txHash);
  assert.equal(duplicate.transactionHash, txHash);
  assert.equal(fixture.signingPort.sent.length, 1);
  assert.equal(fixture.state.get(fixture.built.command.idempotencyKey)?.status, "CONFIRMED");
});

test("IK worker rejects stale decisions, opaque/wrong leaves, bad DID binding, and unauthorized routes", async () => {
  const stale = await setup();
  stale.decisions.readDecision = async () => ({
    revision: 2n, evidenceDigest: stale.built.command.sourceDecisionDigest, approved: true,
    subjectId, wallet, did, expiresAt: stale.built.command.expiresAt, attributes: [1n, 1n, 0n, 0n] as const,
  });
  await assert.rejects(stale.worker.handle(serializeIkCommand(stale.built.command)), /stale/);

  const wrongLeaf = await setup();
  const wrongCommitment = `0x${"01".repeat(32)}` as const;
  const wrongDigest = anchorCalldataDigest({
    functionName: "issueCredential", anchor, regimeHash, did, commitment: wrongCommitment,
    expiresAt: wrongLeaf.built.command.expiresAt, ikId,
  });
  await assert.rejects(wrongLeaf.worker.handle({
    ...serializeIkCommand(wrongLeaf.built.command), commitment: wrongCommitment, calldataDigest: wrongDigest,
  }), /recomputed leaf/);

  const wrongDid = await setup();
  wrongDid.policy.readDid = async () => ({ exists: true, privateSaltCommitment: `0x${wrongDid.hasher.hash2(BigInt(salt), 0n).toString(16).padStart(64, "0")}` as const, spendingKeyRoot: wrongDid.built.spendingRoot, governanceKeys: [anchor] });
  await assert.rejects(wrongDid.worker.handle(serializeIkCommand(wrongDid.built.command)), /one-wallet/);

  const unauthorized = await setup();
  unauthorized.policy.isIkActiveAndAuthorized = async () => false;
  await assert.rejects(unauthorized.worker.handle(serializeIkCommand(unauthorized.built.command)), /inactive/);
});

test("reorg puts the same command/revision back to pending and restricted signer rejects other targets", async () => {
  const fixture = await setup(false);
  await assert.rejects(fixture.worker.handle(serializeIkCommand(fixture.built.command)), ReorgDetectedError);
  assert.equal(fixture.state.get(fixture.built.command.idempotencyKey)?.status, "PENDING");
  await assert.rejects(fixture.signer.submit({
    functionName: "issueCredential", anchor: wallet, regimeHash, did,
    commitment: fixture.built.command.commitment, expiresAt: fixture.built.command.expiresAt, ikId,
  }), /not allowlisted/);
});
