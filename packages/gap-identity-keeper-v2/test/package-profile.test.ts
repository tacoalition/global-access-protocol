import assert from "node:assert/strict";
import { createHash, createPrivateKey } from "node:crypto";
import test from "node:test";
import { decodeCanonicalCbor } from "../src/cbor";
import {
  computeCredentialLeaf,
  computeOneLeafRoot,
  computeSaltCommitment,
} from "../src/credential-builder";
import { addressToField, createPoseidon2, toBytes32 } from "../src/field";
import {
  builderKeyId, encodeIssuedPlaintext, encodeSeedPlaintext, nodeEd25519Signer, openPackage,
  recipientKeyDigest, sealPackage, type IssuedSlot, type PackageHeader,
} from "../src/package-profile";
import type { ConfirmedPackageSlot } from "../src/package-validation";
import { InMemoryPackageReplayStore } from "../src/package-replay";

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX_LENGTH = 12;

function x25519Public(privateRaw: Uint8Array): Uint8Array {
  const privateKey = createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(privateRaw)]), format: "der", type: "pkcs8" });
  const publicKey = require("node:crypto").createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  assert.equal(publicKey.length, X25519_SPKI_PREFIX_LENGTH + 32);
  return Buffer.from(publicKey).subarray(-32);
}

function ed25519Private(seed: Uint8Array) {
  return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]), format: "der", type: "pkcs8" });
}

test("fixed HPKE/CBOR/Ed25519 seed package vector opens under exact bindings", async () => {
  const hasher = await createPoseidon2();
  const recipientPrivate = new Uint8Array(32).fill(7);
  const recipientPublic = x25519Public(recipientPrivate);
  const signer = nodeEd25519Signer(ed25519Private(new Uint8Array(32).fill(9)));
  const header: PackageHeader = {
    packageType: 1, packageId: `0x${"01".repeat(32)}`, builderKeyId: builderKeyId(signer.rawPublicKey),
    walletBindingDigest: `0x${"02".repeat(32)}`, boundWallet: `0x${"03".repeat(20)}`,
    chainId: 84532, didRegistry: `0x${"04".repeat(20)}`, holderPolicyVersion: 1,
    builderSequence: 1n, createdAt: 1_000n, expiresAt: 1_600n,
    recipientKeyDigest: recipientKeyDigest(recipientPublic), levelPolicyRevision: 1,
  };
  const saltCommitment = toBytes32(computeSaltCommitment(hasher, 6n));
  const spendingRoot = toBytes32(computeOneLeafRoot(
    hasher,
    hasher.hash2(addressToField(header.boundWallet), 0n),
    Number(addressToField(header.boundWallet) & 0xffn),
    8,
  ));
  const plaintext = encodeSeedPlaintext({
    did: `0x${"05".padStart(64, "0")}`, privateSalt: `0x${"06".padStart(64, "0")}`,
    saltCommitment, boundAccount: header.boundWallet,
    expectedSpendingRoot: spendingRoot, reservedDidIndex: 5,
    governanceKeys: [header.boundWallet],
  });
  const envelope = await sealPackage(header, plaintext, recipientPublic, signer, new Uint8Array(32).fill(11));
  assert.equal(
    createHash("sha256").update(envelope).digest("hex"),
    "dd83940182e066d155accc81342b867afea942063287336026965b36a44e3e11",
  );
  const replay = new InMemoryPackageReplayStore();
  const expected = {
    packageType: 1, wallet: header.boundWallet, walletBindingDigest: header.walletBindingDigest,
    didRegistry: header.didRegistry, minimumSequence: 1n, now: 1_200n,
    holderPolicyVersion: 1, levelPolicyRevision: 1,
    content: { packageType: 1 as const, hasher }, replay,
  } as const;
  const opened = await openPackage(envelope, recipientPrivate, signer.rawPublicKey, expected);
  assert.deepEqual(Buffer.from(opened.plaintextBytes), Buffer.from(plaintext));
  assert.equal(opened.replayStatus, "ACCEPTED");
  assert.equal(
    (await openPackage(envelope, recipientPrivate, signer.rawPublicKey, expected)).replayStatus,
    "DUPLICATE",
  );

  const tampered = Uint8Array.from(envelope);
  tampered[tampered.length - 1] ^= 1;
  await assert.rejects(
    openPackage(tampered, recipientPrivate, signer.rawPublicKey, expected),
    /signature/,
  );
});

test("canonical CBOR rejects non-minimal integers, indefinite lengths, and out-of-order maps", () => {
  assert.throws(() => decodeCanonicalCbor(Uint8Array.of(0x18, 0x01)), /non-minimal/);
  assert.throws(() => decodeCanonicalCbor(Uint8Array.of(0x9f, 0xff)), /indefinite/);
  assert.throws(() => decodeCanonicalCbor(Uint8Array.of(0xa2, 0x01, 0x00, 0x00, 0x00)), /out-of-order/);
});

test("issued package recomputes both leaves and binds canonical slot records", async () => {
  const hasher = await createPoseidon2();
  const recipientPrivate = new Uint8Array(32).fill(17);
  const recipientPublic = x25519Public(recipientPrivate);
  const signer = nodeEd25519Signer(ed25519Private(new Uint8Array(32).fill(19)));
  const wallet = `0x${"33".repeat(20)}` as const;
  const did = `0x${"15".padStart(64, "0")}` as const;
  const privateSalt = `0x${"16".padStart(64, "0")}` as const;
  const policyId = `0x${"17".padStart(64, "0")}` as const;
  const identityRoute = {
    anchor: `0x${"41".repeat(20)}` as const,
    regimeHash: `0x${"18".padStart(64, "0")}` as const,
    ikId: `0x${"19".padStart(64, "0")}` as const,
    expiresAt: 2_000n,
  };
  const fundRoute = {
    anchor: `0x${"42".repeat(20)}` as const,
    regimeHash: `0x${"20".padStart(64, "0")}` as const,
    ikId: `0x${"21".padStart(64, "0")}` as const,
    expiresAt: 1_900n,
  };
  const identityCommitment = computeCredentialLeaf(hasher, {
    chainId: 84532,
    ...identityRoute,
    did,
    privateSalt,
    attributes: [1n, 1n, 0n, 0n],
  });
  const fundCommitment = computeCredentialLeaf(hasher, {
    chainId: 84532,
    ...fundRoute,
    did,
    privateSalt,
    attributes: [1n, 1n, 0n, 0n],
  });
  const issuedSlots: [IssuedSlot, IssuedSlot] = [
    {
      ita: identityRoute.anchor,
      regimeHash: identityRoute.regimeHash,
      ikId: identityRoute.ikId,
      expiresAt: identityRoute.expiresAt,
      slotCredentialRevision: 1n,
      commitment: identityCommitment,
      treeIndex: 21,
      issueTxHash: `0x${"aa".repeat(32)}`,
      issueBlockHash: `0x${"bb".repeat(32)}`,
    },
    {
      ita: fundRoute.anchor,
      regimeHash: fundRoute.regimeHash,
      ikId: fundRoute.ikId,
      expiresAt: fundRoute.expiresAt,
      slotCredentialRevision: 1n,
      commitment: fundCommitment,
      treeIndex: 21,
      issueTxHash: `0x${"cc".repeat(32)}`,
      issueBlockHash: `0x${"dd".repeat(32)}`,
    },
  ];
  const confirmed: [ConfirmedPackageSlot, ConfirmedPackageSlot] = issuedSlots.map((slot) => ({
    anchor: slot.ita,
    regimeHash: slot.regimeHash,
    ikId: slot.ikId,
    credentialRevision: 1n,
    commitment: slot.commitment,
    expiresAt: slot.expiresAt,
    treeIndex: slot.treeIndex,
    issueTxHash: slot.issueTxHash,
    issueBlockHash: slot.issueBlockHash,
    canonical: true,
    revoked: false,
  })) as [ConfirmedPackageSlot, ConfirmedPackageSlot];
  const header: PackageHeader = {
    packageType: 2,
    packageId: `0x${"22".repeat(32)}`,
    builderKeyId: builderKeyId(signer.rawPublicKey),
    walletBindingDigest: `0x${"23".repeat(32)}`,
    boundWallet: wallet,
    chainId: 84532,
    didRegistry: `0x${"24".repeat(20)}`,
    holderPolicyVersion: 1,
    builderSequence: 2n,
    createdAt: 1_000n,
    expiresAt: 1_600n,
    recipientKeyDigest: recipientKeyDigest(recipientPublic),
    levelPolicyRevision: 1,
  };
  const plaintext = encodeIssuedPlaintext({
    did,
    privateSalt,
    attributes: [1n, 1n, 0n, 0n, 1n, 1n, 0n, 0n],
    slots: issuedSlots,
    policyId,
    holderPolicyVersion: 1,
    levelPolicyRevision: 1,
  });
  const envelope = await sealPackage(header, plaintext, recipientPublic, signer, new Uint8Array(32).fill(23));
  const expected = {
    packageType: 2 as const,
    wallet,
    walletBindingDigest: header.walletBindingDigest,
    didRegistry: header.didRegistry,
    minimumSequence: 2n,
    now: 1_200n,
    holderPolicyVersion: 1,
    levelPolicyRevision: 1,
    content: { packageType: 2 as const, hasher, did, privateSalt, policyId, slots: confirmed },
    replay: new InMemoryPackageReplayStore(),
  };
  assert.equal(
    (await openPackage(envelope, recipientPrivate, signer.rawPublicKey, expected)).replayStatus,
    "ACCEPTED",
  );

  const badPlaintext = encodeIssuedPlaintext({
    did,
    privateSalt,
    attributes: [1n, 0n, 0n, 0n, 1n, 1n, 0n, 0n],
    slots: issuedSlots,
    policyId,
    holderPolicyVersion: 1,
    levelPolicyRevision: 1,
  });
  const badEnvelope = await sealPackage(header, badPlaintext, recipientPublic, signer, new Uint8Array(32).fill(25));
  await assert.rejects(
    openPackage(badEnvelope, recipientPrivate, signer.rawPublicKey, {
      ...expected,
      replay: new InMemoryPackageReplayStore(),
    }),
    /attributes/,
  );
});
