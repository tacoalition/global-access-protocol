import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalIdempotencyKeyV2,
  parseIkCommandV2,
  serializeIkCommandV2,
  type IssueCredentialCommandV2,
} from "../src/command-schema-v2";
import { parseIkCommand } from "../src/command-schema";
import { computeCredentialLeaf } from "../src/credential-builder";
import { createPoseidon2 } from "../src/field";
import {
  IdentityAnchorClient,
  anchorCalldataDigest,
  type IdentityAnchorReadPort,
} from "../src/identity-anchor-client";
import { SchemaRestrictedSigner, type AnchorMutation, type IkSigningPort } from "../src/signer";
import { AssignedSlotSpendingWalletSet, GAP_SPENDING_WALLET_SET_V2 } from "../src/spending-wallet-set";
import {
  GapIdentityKeeperSubjectWorkerV2,
  InMemoryWorkerStateStoreV2,
  type AuthoritativeWalletSetPortV2,
  type IkPolicyReadPortV2,
} from "../src/worker-v2";

/** One blind for this file: these tests are about slots and packaging, not about the blind. */
const TEST_BLIND = 0x5eedn;
const TEST_BLIND_HEX = `0x${TEST_BLIND.toString(16).padStart(64, "0")}` as `0x${string}`;

const address = (value: bigint) => `0x${value.toString(16).padStart(40, "0")}` as const;
const walletA = address(0x1001n);
const walletB = address(0x1101n);
const controller = address(0xc011n);
const anchor = address(0xa11n);
const signerAddress = address(0x511n);
const regimeHash = `0x${"22".repeat(32)}` as const;
const did = `0x${"03".padStart(64, "0")}` as const;
const ikId = `0x${"04".padStart(64, "0")}` as const;
const salt = `0x${"05".padStart(64, "0")}` as const;
const subjectId = "123e4567-e89b-42d3-a456-426614174000";
const txHash = `0x${"55".repeat(32)}` as const;

class FakeSigningPort implements IkSigningPort {
  readonly address = signerAddress;
  readonly sent: AnchorMutation[] = [];
  async sendCredentialMutation(mutation: AnchorMutation) {
    this.sent.push(mutation);
    return txHash;
  }
}

async function setup() {
  const hasher = await createPoseidon2();
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(walletA, 0n);
  set.add(walletB, 1n);
  const expiresAt = 1_800_000_000n;
  const commitment = computeCredentialLeaf(hasher, {
    chainId: 84532,
    anchor,
    regimeHash,
    did,
    ikId,
    attributes: [1n, 1n, 0n, 0n],
    privateSalt: salt,
    expiresAt,
  });
  const calldataDigest = anchorCalldataDigest({
    functionName: "issueCredential",
    anchor,
    regimeHash,
    did,
    commitment,
    expiresAt,
    ikId,
  });
  const draft: IssueCredentialCommandV2 = {
    schemaVersion: 2,
    credentialScope: "SUBJECT",
    walletSetProfile: GAP_SPENDING_WALLET_SET_V2,
    slot: "IDENTITY",
    action: "ISSUE",
    chainId: 84532,
    anchor,
    regimeHash,
    activeDID: did,
    ikId,
    subjectId,
    sourceDecisionRevision: 1n,
    credentialRevision: 1n,
    sourceDecisionDigest: `0x${"66".repeat(32)}`,
    calldataDigest,
    idempotencyKey: "",
    expectedSpendingRoot: set.root(),
    walletSetRevision: 2n,
    attributes: [1n, 1n, 0n, 0n],
    privateSalt: salt,
    expiresAt,
    commitment,
  };
  const command = { ...draft, idempotencyKey: canonicalIdempotencyKeyV2(draft) };
  const signingPort = new FakeSigningPort();
  const signer = new SchemaRestrictedSigner(signingPort, anchor, ikId);
  const emptyCredential = {
    commitment: `0x${"00".repeat(32)}` as const,
    issuerIKId: ikId,
    issuedAt: 0n,
    expiresAt: 0n,
    revoked: false,
    treeIndex: 3,
  };
  const reader: IdentityAnchorReadPort = {
    async simulateCredentialMutation() {},
    async waitForCanonicalReceipt(transactionHash) {
      return {
        transactionHash,
        blockNumber: 100n,
        blockHash: `0x${"77".repeat(32)}` as const,
        canonical: true,
        status: "SUCCESS",
        from: signerAddress,
        to: anchor,
        calldataDigest,
      };
    },
    async getCredential() {
      return { ...emptyCredential, commitment, issuedAt: 10n, expiresAt };
    },
  };
  const policy: IkPolicyReadPortV2 = {
    async readDid() {
      return {
        exists: true,
        privateSaltCommitment: `0x${hasher.hash2(BigInt(salt), 0n).toString(16).padStart(64, "0")}`,
        spendingKeyRoot: set.root(),
        governanceKeys: [controller],
      };
    },
    async isIkActiveAndAuthorized() { return true; },
    async readCredential() { return emptyCredential; },
  };
  const decisions = {
    async readSubjectDecision() {
      return {
        revision: 1n,
        evidenceDigest: command.sourceDecisionDigest,
        approved: true,
        subjectId,
        did,
        expiresAt,
      };
    },
  };
  const walletSets: AuthoritativeWalletSetPortV2 = {
    async readWalletSet() {
      return {
        subjectId,
        activeDID: did,
        walletSet: set.snapshot(),
        governanceControllers: [controller],
      };
    },
  };
  const state = new InMemoryWorkerStateStoreV2();
  const client = new IdentityAnchorClient(reader, signer, 2);
  const worker = new GapIdentityKeeperSubjectWorkerV2(
    "IDENTITY",
    hasher,
    decisions,
    walletSets,
    policy,
    client,
    state,
    signerAddress,
    () => 1_799_999_000n,
  );
  return { command, worker, state, signingPort, set, walletSets, policy };
}

test("V2 command is explicit, subject-scoped, and cannot be parsed as V1", async () => {
  const fixture = await setup();
  const json = serializeIkCommandV2(fixture.command);
  assert.deepEqual(parseIkCommandV2(json), fixture.command);
  assert.equal("wallet" in json, false);
  assert.throws(() => parseIkCommand(json), /unsupported IK command version/);
  assert.throws(
    () => parseIkCommandV2({ ...json, schemaVersion: 1 }),
    /unsupported V2 IK command/,
  );
  assert.throws(
    () => parseIkCommandV2({ ...json, wallet: walletA }),
    /unexpected V2 IK command key/,
  );
});

test("V2 worker issues one subject credential for a two-wallet root under a stable controller", async () => {
  const fixture = await setup();
  const json = serializeIkCommandV2(fixture.command);
  const result = await fixture.worker.handle(json);
  const duplicate = await fixture.worker.handle(json);
  assert.equal(result.transactionHash, txHash);
  assert.equal(duplicate.transactionHash, txHash);
  assert.equal(fixture.signingPort.sent.length, 1);
  assert.equal(fixture.set.proof(walletA).slot, 1);
  assert.equal(fixture.set.proof(walletB).slot, 2);
  assert.equal(fixture.state.get(fixture.command.idempotencyKey)?.status, "CONFIRMED");
});

test("V2 worker rejects stale wallet-set revision/root and wallet-governance overlap", async () => {
  const staleRevision = await setup();
  staleRevision.walletSets.readWalletSet = async () => ({
    subjectId,
    activeDID: did,
    walletSet: { ...staleRevision.set.snapshot(), revision: 3n },
    governanceControllers: [controller],
  });
  await assert.rejects(
    staleRevision.worker.handle(serializeIkCommandV2(staleRevision.command)),
    /stale V2 wallet-set revision/,
  );

  const staleRoot = await setup();
  staleRoot.walletSets.readWalletSet = async () => ({
    subjectId,
    activeDID: did,
    walletSet: { ...staleRoot.set.snapshot(), root: `0x${"01".repeat(32)}` },
    governanceControllers: [controller],
  });
  await assert.rejects(
    staleRoot.worker.handle(serializeIkCommandV2(staleRoot.command)),
    /stale V2 wallet-set root/,
  );

  const overlap = await setup();
  overlap.walletSets.readWalletSet = async () => ({
    subjectId,
    activeDID: did,
    walletSet: overlap.set.snapshot(),
    governanceControllers: [walletA],
  });
  await assert.rejects(
    overlap.worker.handle(serializeIkCommandV2(overlap.command)),
    /separate from spending wallets/,
  );
});
