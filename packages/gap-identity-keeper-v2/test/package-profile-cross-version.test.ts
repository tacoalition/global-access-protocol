import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import test from "node:test";
import { computeOneLeafRoot, computeSaltCommitment } from "../src/credential-builder";
import { addressToField, createPoseidon2, toBytes32 } from "../src/field";
import { encodeSeedPlaintextV2 } from "../src/package-content-v2";
import { openPackageV2, sealPackageV2 } from "../src/package-envelope-v2";
import {
  builderKeyId,
  encodeSeedPlaintext,
  nodeEd25519Signer,
  openPackage,
  recipientKeyDigest,
  sealPackage,
  type PackageHeader,
} from "../src/package-profile";
import { InMemoryPackageReplayStore } from "../src/package-replay";
import {
  AssignedSlotSpendingWalletSet,
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
} from "../src/spending-wallet-set";

/** One blind for this file: these tests are about slots and packaging, not about the blind. */
const TEST_BLIND = 0x5eedn;
const TEST_BLIND_HEX = `0x${TEST_BLIND.toString(16).padStart(64, "0")}` as `0x${string}`;

const address = (value: bigint) => `0x${value.toString(16).padStart(40, "0")}` as const;

function key(kind: "x25519" | "ed25519", seed: Uint8Array) {
  const algorithm = kind === "x25519" ? "656e" : "6570";
  return createPrivateKey({
    key: Buffer.concat([Buffer.from(`302e020100300506032b${algorithm}04220420`, "hex"), Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

test("V1 and V2 package envelopes are mutually rejected across profiles", async () => {
  const hasher = await createPoseidon2();
  const wallet = address(0x1001n);
  const controller = address(0xc011n);
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(wallet, 0n);
  const proof = set.proof(wallet);
  const did = `0x${"05".padStart(64, "0")}` as const;
  const privateSalt = `0x${"06".padStart(64, "0")}` as const;
  const recipientPrivate = new Uint8Array(32).fill(7);
  const recipientPublic = Buffer.from(createPublicKey(key("x25519", recipientPrivate)).export({
    format: "der",
    type: "spki",
  }) as Buffer).subarray(-32);
  const signer = nodeEd25519Signer(key("ed25519", new Uint8Array(32).fill(9)));
  const header: PackageHeader = {
    packageType: 1,
    packageId: `0x${"01".repeat(32)}`,
    builderKeyId: builderKeyId(signer.rawPublicKey),
    walletBindingDigest: `0x${"02".repeat(32)}`,
    boundWallet: wallet,
    chainId: 84532,
    didRegistry: address(0xd1dn),
    holderPolicyVersion: 1,
    builderSequence: 1n,
    createdAt: 1_000n,
    expiresAt: 1_600n,
    recipientKeyDigest: recipientKeyDigest(recipientPublic),
    levelPolicyRevision: 1,
  };
  const commonExpected = {
    packageType: 1 as const,
    wallet,
    walletBindingDigest: header.walletBindingDigest,
    didRegistry: header.didRegistry,
    minimumSequence: 1n,
    now: 1_200n,
    holderPolicyVersion: 1,
    levelPolicyRevision: 1,
  };

  const v2Plaintext = encodeSeedPlaintextV2({
    did,
    privateSalt,
    saltCommitment: toBytes32(computeSaltCommitment(hasher, BigInt(privateSalt))),
    boundAccount: wallet,
    walletMembership: {
      profile: GAP_SPENDING_WALLET_SET_V2,
      schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
      root: proof.root,
      revision: 1n,
      assignedSlot: proof.slot,
      siblings: proof.siblings,
      pathIndices: proof.pathIndices,
    },
    reservedDidIndex: 5,
    governanceControllers: [controller],
  });
  const v2Envelope = await sealPackageV2(
    header,
    v2Plaintext,
    recipientPublic,
    signer,
    new Uint8Array(32).fill(11),
  );
  await assert.rejects(
    openPackage(v2Envelope, recipientPrivate, signer.rawPublicKey, {
      ...commonExpected,
      content: { packageType: 1, hasher },
      replay: new InMemoryPackageReplayStore(),
    }),
    /signature|profile|schema/,
  );

  const oneWalletRoot = computeOneLeafRoot(
    hasher,
    hasher.hash2(addressToField(wallet), 0n),
    Number(addressToField(wallet) & 0xffn),
    8,
  );
  const v1Plaintext = encodeSeedPlaintext({
    did,
    privateSalt,
    saltCommitment: toBytes32(computeSaltCommitment(hasher, BigInt(privateSalt))),
    boundAccount: wallet,
    expectedSpendingRoot: toBytes32(oneWalletRoot),
    expectedSpendingBlind: TEST_BLIND_HEX,
    reservedDidIndex: 5,
    governanceKeys: [wallet],
  });
  const v1Envelope = await sealPackage(
    header,
    v1Plaintext,
    recipientPublic,
    signer,
    new Uint8Array(32).fill(13),
  );
  await assert.rejects(
    openPackageV2(v1Envelope, recipientPrivate, signer.rawPublicKey, {
      ...commonExpected,
      content: {
        packageType: 1,
        hasher,
        expectedSpendingRoot: set.root(), expectedSpendingBlind: TEST_BLIND_HEX,
        walletSetRevision: 1n,
        governanceControllers: [controller],
      },
      replay: new InMemoryPackageReplayStore(),
    }),
    /signature|profile|schema/,
  );
});
