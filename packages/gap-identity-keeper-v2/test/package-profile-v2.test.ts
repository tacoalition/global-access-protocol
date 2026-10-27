import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import test from "node:test";
import { AssignedWalletCredentialBuilderV2 } from "../src/credential-builder-v2";
import { computeCredentialLeaf } from "../src/credential-builder";
import { createPoseidon2, toBytes32 } from "../src/field";
import { encodeIssuedPlaintextV2, encodeSeedPlaintextV2 } from "../src/package-content-v2";
import { openPackageV2, sealPackageV2 } from "../src/package-envelope-v2";
import type {
  PackageHeaderV2,
  PackagedSpendingWalletWitnessV2,
} from "../src/package-types-v2";
import {
  builderKeyId,
  nodeEd25519Signer,
  recipientKeyDigest,
  type IssuedSlot,
} from "../src/package-profile";
import { InMemoryPackageReplayStore } from "../src/package-replay";
import type { ConfirmedPackageSlot } from "../src/package-validation";
import {
  AssignedSlotSpendingWalletSet,
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
  type SpendingWalletMembershipProof,
} from "../src/spending-wallet-set";

/** One blind for this file: these tests are about slots and packaging, not about the blind. */
const TEST_BLIND = 0x5eedn;
const TEST_BLIND_HEX = `0x${TEST_BLIND.toString(16).padStart(64, "0")}` as `0x${string}`;

const address = (value: bigint) => `0x${value.toString(16).padStart(40, "0")}` as const;
const walletA = address(0x1001n);
const walletB = address(0x1101n);
const controller = address(0xc011n);

function privateKey(kind: "x25519" | "ed25519", seed: Uint8Array) {
  const algorithm = kind === "x25519" ? "656e" : "6570";
  return createPrivateKey({
    key: Buffer.concat([Buffer.from(`302e020100300506032b${algorithm}04220420`, "hex"), Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

function x25519Public(seed: Uint8Array): Uint8Array {
  return Buffer.from(createPublicKey(privateKey("x25519", seed)).export({
    format: "der",
    type: "spki",
  }) as Buffer).subarray(-32);
}

function packaged(
  proof: SpendingWalletMembershipProof,
  revision: bigint,
): PackagedSpendingWalletWitnessV2 {
  return {
    profile: GAP_SPENDING_WALLET_SET_V2,
    schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
    root: proof.root,
    revision,
    assignedSlot: proof.slot,
    siblings: proof.siblings,
    pathIndices: proof.pathIndices,
  };
}

function header(
  wallet: `0x${string}`,
  packageType: 1 | 2,
  packageIdByte: string,
  signerKeyId: `0x${string}`,
  recipientDigest: `0x${string}`,
): PackageHeaderV2 {
  return {
    packageType,
    packageId: `0x${packageIdByte.repeat(32)}`,
    builderKeyId: signerKeyId,
    walletBindingDigest: `0x${packageIdByte.repeat(32)}`,
    boundWallet: wallet,
    chainId: 84532,
    didRegistry: address(0xd1dn),
    holderPolicyVersion: 1,
    builderSequence: BigInt(`0x${packageIdByte}`),
    createdAt: 1_000n,
    expiresAt: 1_600n,
    recipientKeyDigest: recipientDigest,
    levelPolicyRevision: 1,
  };
}

test("V2 seed builder consumes a collision-safe assigned-slot snapshot and stable controller", async () => {
  const hasher = await createPoseidon2();
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(walletA, 0n);
  set.add(walletB, 1n);
  assert.equal(Number(BigInt(walletA) & 0xffn), Number(BigInt(walletB) & 0xffn));
  assert.equal(set.proof(walletA).slot, 1);
  assert.equal(set.proof(walletB).slot, 2);

  let sampled = 0;
  const builder = new AssignedWalletCredentialBuilderV2(hasher, () => {
    const output = new Uint8Array(32);
    output[31] = ++sampled;
    return output;
  });
  const result = await builder.reserveSeed({
    boundWallet: walletA,
    governanceControllers: [controller],
    walletSet: set.snapshot(),
    membership: set.proof(walletA),
  }, {
    async areAllSlotsEmpty() { return true; },
    async tryReserve() {
      return { reservationId: "v2-reservation", finalizedBlockHash: `0x${"aa".repeat(32)}` };
    },
  });
  assert.equal(result.seed.walletMembership.root, set.root());
  assert.equal(result.seed.walletMembership.revision, 2n);
  assert.equal(result.seed.walletMembership.assignedSlot, 1);
  assert.deepEqual(result.seed.governanceControllers, [controller]);
  assert.equal(
    result.didLeaf,
    toBytes32(hasher.hash2(
      hasher.hash2(BigInt(result.seed.did), BigInt(result.seed.saltCommitment)),
      BigInt(set.root()),
    )),
  );
  const recipientPrivate = new Uint8Array(32).fill(5);
  const recipientPublic = x25519Public(recipientPrivate);
  const signer = nodeEd25519Signer(privateKey("ed25519", new Uint8Array(32).fill(6)));
  const packageHeader = header(
    walletA,
    1,
    "10",
    builderKeyId(signer.rawPublicKey),
    recipientKeyDigest(recipientPublic),
  );
  const plaintext = encodeSeedPlaintextV2(result.seed);
  const envelope = await sealPackageV2(
    packageHeader,
    plaintext,
    recipientPublic,
    signer,
    new Uint8Array(32).fill(8),
  );
  const opened = await openPackageV2(envelope, recipientPrivate, signer.rawPublicKey, {
    packageType: 1,
    wallet: walletA,
    walletBindingDigest: packageHeader.walletBindingDigest,
    didRegistry: packageHeader.didRegistry,
    minimumSequence: packageHeader.builderSequence,
    now: 1_200n,
    holderPolicyVersion: 1,
    levelPolicyRevision: 1,
    content: {
      packageType: 1,
      hasher,
      expectedSpendingRoot: set.root(), expectedSpendingBlind: TEST_BLIND_HEX,
      walletSetRevision: 2n,
      governanceControllers: [controller],
    },
    replay: new InMemoryPackageReplayStore(),
  });
  assert.deepEqual(Buffer.from(opened.plaintextBytes), Buffer.from(plaintext));
  assert.throws(
    () => encodeSeedPlaintextV2({ ...result.seed, governanceControllers: [walletA] }),
    /separate from spending wallets/,
  );
  assert.throws(
    () => encodeSeedPlaintextV2({ ...result.seed, governanceControllers: [] }),
    /1\.\.5 stable controllers/,
  );
  assert.throws(
    () => encodeSeedPlaintextV2({
      ...result.seed,
      governanceControllers: Array.from({ length: 6 }, (_, index) => address(0xd000n + BigInt(index))),
    }),
    /1\.\.5 stable controllers/,
  );
});

test("issued V2 packages carry distinct membership witnesses for colliding wallets under one DID", async () => {
  const hasher = await createPoseidon2();
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(walletA, 0n);
  set.add(walletB, 1n);
  const did = `0x${"15".padStart(64, "0")}` as const;
  const salt = `0x${"16".padStart(64, "0")}` as const;
  const policyId = `0x${"17".padStart(64, "0")}` as const;
  const routes = [
    { ita: address(0x411n), regimeHash: `0x${"18".padStart(64, "0")}` as const,
      ikId: `0x${"19".padStart(64, "0")}` as const, expiresAt: 2_000n },
    { ita: address(0x422n), regimeHash: `0x${"20".padStart(64, "0")}` as const,
      ikId: `0x${"21".padStart(64, "0")}` as const, expiresAt: 1_900n },
  ] as const;
  const slots = routes.map((route, index) => ({
    ...route,
    slotCredentialRevision: 1n,
    commitment: computeCredentialLeaf(hasher, {
      chainId: 84532, anchor: route.ita, regimeHash: route.regimeHash, did,
      ikId: route.ikId, attributes: [1n, 1n, 0n, 0n], privateSalt: salt, expiresAt: route.expiresAt,
    }),
    treeIndex: 21,
    issueTxHash: `0x${(index === 0 ? "aa" : "cc").repeat(32)}` as const,
    issueBlockHash: `0x${(index === 0 ? "bb" : "dd").repeat(32)}` as const,
  })) as unknown as [IssuedSlot, IssuedSlot];
  const confirmed = slots.map((slot) => ({
    anchor: slot.ita, regimeHash: slot.regimeHash, ikId: slot.ikId,
    credentialRevision: 1n, commitment: slot.commitment, expiresAt: slot.expiresAt,
    treeIndex: slot.treeIndex, issueTxHash: slot.issueTxHash,
    issueBlockHash: slot.issueBlockHash, canonical: true, revoked: false,
  })) as [ConfirmedPackageSlot, ConfirmedPackageSlot];
  const recipientPrivate = new Uint8Array(32).fill(7);
  const recipientPublic = x25519Public(recipientPrivate);
  const signer = nodeEd25519Signer(privateKey("ed25519", new Uint8Array(32).fill(9)));
  const replay = new InMemoryPackageReplayStore();

  for (const [index, wallet] of [walletA, walletB].entries()) {
    const proof = set.proof(wallet);
    const membership = packaged(proof, set.snapshot().revision);
    const plaintext = encodeIssuedPlaintextV2({
      did, privateSalt: salt, attributes: [1n, 1n, 0n, 0n, 1n, 1n, 0n, 0n], slots,
      policyId, holderPolicyVersion: 1, levelPolicyRevision: 1,
      walletMembership: membership,
    });
    const packageHeader = header(
      wallet,
      2,
      index === 0 ? "22" : "23",
      builderKeyId(signer.rawPublicKey),
      recipientKeyDigest(recipientPublic),
    );
    const envelope = await sealPackageV2(
      packageHeader,
      plaintext,
      recipientPublic,
      signer,
      new Uint8Array(32).fill(11 + index),
    );
    const opened = await openPackageV2(envelope, recipientPrivate, signer.rawPublicKey, {
      packageType: 2, wallet, walletBindingDigest: packageHeader.walletBindingDigest,
      didRegistry: packageHeader.didRegistry, minimumSequence: packageHeader.builderSequence,
      now: 1_200n, holderPolicyVersion: 1, levelPolicyRevision: 1,
      content: { packageType: 2, hasher, did, privateSalt: salt, policyId, slots: confirmed,
        expectedSpendingRoot: set.root(), expectedSpendingBlind: TEST_BLIND_HEX, walletSetRevision: 2n },
      replay,
    });
    assert.equal(opened.replayStatus, "ACCEPTED");
    assert.equal(opened.walletMembership.assignedSlot, proof.slot);
    assert.equal(membership.assignedSlot, index + 1);
  }

  const wrongPlaintext = encodeIssuedPlaintextV2({
    did, privateSalt: salt, attributes: [1n, 1n, 0n, 0n, 1n, 1n, 0n, 0n], slots,
    policyId, holderPolicyVersion: 1, levelPolicyRevision: 1,
    walletMembership: packaged(set.proof(walletA), 2n),
  });
  const wrongHeader = header(
    walletB,
    2,
    "24",
    builderKeyId(signer.rawPublicKey),
    recipientKeyDigest(recipientPublic),
  );
  const wrongEnvelope = await sealPackageV2(
    wrongHeader,
    wrongPlaintext,
    recipientPublic,
    signer,
    new Uint8Array(32).fill(31),
  );
  await assert.rejects(
    openPackageV2(wrongEnvelope, recipientPrivate, signer.rawPublicKey, {
      packageType: 2, wallet: walletB, walletBindingDigest: wrongHeader.walletBindingDigest,
      didRegistry: wrongHeader.didRegistry, minimumSequence: wrongHeader.builderSequence,
      now: 1_200n, holderPolicyVersion: 1, levelPolicyRevision: 1,
      content: { packageType: 2, hasher, did, privateSalt: salt, policyId, slots: confirmed,
        expectedSpendingRoot: set.root(), expectedSpendingBlind: TEST_BLIND_HEX, walletSetRevision: 2n },
      replay: new InMemoryPackageReplayStore(),
    }),
    /proof does not match root/,
  );
});
