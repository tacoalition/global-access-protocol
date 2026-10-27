import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify as nodeVerify,
} from "node:crypto";
import { cborMap, decodeCanonicalCbor, encodeCbor, requireMap, type CborValue } from "./cbor";
import { hpkeOpen, hpkeSeal } from "./hpke";
import { validatePackagePlaintextV2 } from "./package-content-v2";
import type { PackageExpectationsV2, PackageHeaderV2 } from "./package-types-v2";
import {
  builderKeyId,
  recipientKeyDigest,
  type PackageSigner,
} from "./package-profile";
import type { Address, Bytes32 } from "./types";

export const PACKAGE_PROFILE_V2 = "DSI_CREDENTIAL_PACKAGE_HPKE_V2";
export const PACKAGE_SCHEMA_REVISION_V2 = 2;
const SIGNATURE_DOMAIN_V2 = Buffer.from("DSI_CREDENTIAL_PACKAGE_SIG_V2", "ascii");

function bytes(hex: string, length: number, label: string): Uint8Array {
  if (!new RegExp(`^0x[0-9a-fA-F]{${length * 2}}$`).test(hex)) {
    throw new Error(`${label} must be ${length} bytes`);
  }
  return Buffer.from(hex.slice(2), "hex");
}

function hex(value: Uint8Array): Bytes32 {
  return `0x${Buffer.from(value).toString("hex")}`;
}

function sha256(...parts: readonly Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function uint(map: ReadonlyMap<number, CborValue>, key: number, label: string): bigint {
  const value = map.get(key);
  if (typeof value !== "bigint") throw new Error(`${label} must be a CBOR uint`);
  return value;
}

function bstr(
  map: ReadonlyMap<number, CborValue>,
  key: number,
  length: number,
  label: string,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${label} has wrong length`);
  }
  return value;
}

function assertUint(value: bigint | number, bits: number, label: string): void {
  const converted = BigInt(value);
  if (converted < 0n || converted >= 1n << BigInt(bits)) {
    throw new Error(`${label} exceeds uint${bits}`);
  }
}

export function encodeHeaderV2(header: PackageHeaderV2): Uint8Array {
  assertUint(header.holderPolicyVersion, 32, "holderPolicyVersion");
  assertUint(header.builderSequence, 64, "builderSequence");
  assertUint(header.createdAt, 64, "createdAt");
  assertUint(header.expiresAt, 64, "expiresAt");
  assertUint(header.levelPolicyRevision, 32, "levelPolicyRevision");
  if (header.expiresAt < header.createdAt || header.expiresAt - header.createdAt > 600n) {
    throw new Error("package delivery expiry must be within ten minutes");
  }
  return encodeCbor(cborMap([
    [0, 2], [1, header.packageType], [2, bytes(header.packageId, 32, "packageId")],
    [3, bytes(header.builderKeyId, 32, "builderKeyId")],
    [4, bytes(header.walletBindingDigest, 32, "walletBindingDigest")],
    [5, bytes(header.boundWallet, 20, "boundWallet")], [6, header.chainId],
    [7, bytes(header.didRegistry, 20, "didRegistry")], [8, PACKAGE_SCHEMA_REVISION_V2],
    [9, header.holderPolicyVersion], [10, header.builderSequence], [11, header.createdAt],
    [12, header.expiresAt], [13, bytes(header.recipientKeyDigest, 32, "recipientKeyDigest")],
    [14, header.levelPolicyRevision],
  ]));
}

export function packageInfoV2(header: PackageHeaderV2): Uint8Array {
  return sha256(encodeCbor([
    PACKAGE_PROFILE_V2,
    header.packageType,
    header.chainId,
    bytes(header.didRegistry, 20, "didRegistry"),
    PACKAGE_SCHEMA_REVISION_V2,
  ]));
}

export async function sealPackageV2(
  header: PackageHeaderV2,
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  signer: PackageSigner,
  ephemeralPrivateKey?: Uint8Array,
): Promise<Uint8Array> {
  if (header.builderKeyId !== builderKeyId(signer.rawPublicKey)) {
    throw new Error("builder key ID mismatch");
  }
  if (header.recipientKeyDigest !== recipientKeyDigest(recipientPublicKey)) {
    throw new Error("recipient key digest mismatch");
  }
  const rawHeader = encodeHeaderV2(header);
  const sealed = hpkeSeal(
    recipientPublicKey,
    packageInfoV2(header),
    rawHeader,
    plaintext,
    ephemeralPrivateKey,
  );
  const digest = sha256(SIGNATURE_DOMAIN_V2, rawHeader, sealed.enc, sealed.ciphertext);
  const signature = await signer.signDigest(digest);
  if (signature.length !== 64) throw new Error("Ed25519 signature must be 64 bytes");
  return encodeCbor(cborMap([
    [0, decodeCanonicalCbor(rawHeader)],
    [1, sealed.enc],
    [2, sealed.ciphertext],
    [3, signature],
  ]));
}

function validateHeader(
  header: ReadonlyMap<number, CborValue>,
  expected: PackageExpectationsV2,
  recipientPublic: Uint8Array,
): void {
  if (uint(header, 0, "profileVersion") !== 2n || uint(header, 8, "schema") !== 2n) {
    throw new Error("V2 package profile/schema mismatch");
  }
  if (uint(header, 1, "packageType") !== BigInt(expected.packageType)) {
    throw new Error("V2 package type mismatch");
  }
  if (uint(header, 6, "chainId") !== 84532n) throw new Error("V2 package chain mismatch");
  if (uint(header, 9, "holder policy") !== BigInt(expected.holderPolicyVersion)) {
    throw new Error("holder policy mismatch");
  }
  if (uint(header, 14, "level policy") !== BigInt(expected.levelPolicyRevision)) {
    throw new Error("level policy mismatch");
  }
  if (uint(header, 10, "sequence") < expected.minimumSequence) throw new Error("stale builder sequence");
  const createdAt = uint(header, 11, "createdAt");
  const expiresAt = uint(header, 12, "expiresAt");
  if (
    createdAt > expected.now ||
    expiresAt < expected.now ||
    expiresAt < createdAt ||
    expiresAt - createdAt > 600n
  ) {
    throw new Error("package is not currently deliverable");
  }
  const checks: Array<[number, string, number]> = [
    [4, expected.walletBindingDigest, 32],
    [5, expected.wallet, 20],
    [7, expected.didRegistry, 20],
  ];
  for (const [key, expectedValue, length] of checks) {
    if (!Buffer.from(bstr(header, key, length, "header binding")).equals(bytes(expectedValue, length, "expected binding"))) {
      throw new Error("package binding mismatch");
    }
  }
  if (!Buffer.from(bstr(header, 13, 32, "recipient digest")).equals(bytes(recipientKeyDigest(recipientPublic), 32, "recipient digest"))) {
    throw new Error("wrong recipient key");
  }
}

function publicFromPrivate(privateKey: Uint8Array): Uint8Array {
  const prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  const privateObject = createPrivateKey({
    key: Buffer.concat([prefix, Buffer.from(privateKey)]),
    format: "der",
    type: "pkcs8",
  });
  return Buffer.from(createPublicKey(privateObject).export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
}

function headerForInfo(map: ReadonlyMap<number, CborValue>): PackageHeaderV2 {
  return {
    packageType: Number(uint(map, 1, "packageType")) as 1 | 2,
    packageId: hex(bstr(map, 2, 32, "packageId")),
    builderKeyId: hex(bstr(map, 3, 32, "builderKeyId")),
    walletBindingDigest: hex(bstr(map, 4, 32, "bindingDigest")),
    boundWallet: hex(bstr(map, 5, 20, "wallet")) as Address,
    chainId: 84532,
    didRegistry: hex(bstr(map, 7, 20, "registry")) as Address,
    holderPolicyVersion: Number(uint(map, 9, "holderPolicy")),
    builderSequence: uint(map, 10, "sequence"),
    createdAt: uint(map, 11, "createdAt"),
    expiresAt: uint(map, 12, "expiresAt"),
    recipientKeyDigest: hex(bstr(map, 13, 32, "recipientDigest")),
    levelPolicyRevision: Number(uint(map, 14, "levelPolicy")),
  };
}

export async function openPackageV2(
  envelopeBytes: Uint8Array,
  recipientPrivateKey: Uint8Array,
  pinnedBuilderPublicKey: Uint8Array,
  expected: PackageExpectationsV2,
) {
  const envelope = requireMap(decodeCanonicalCbor(envelopeBytes), [0, 1, 2, 3]);
  const header = requireMap(envelope.get(0)!, Array.from({ length: 15 }, (_, key) => key));
  const enc = bstr(envelope, 1, 32, "HPKE enc");
  const ciphertext = envelope.get(2);
  const signature = bstr(envelope, 3, 64, "signature");
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 16) throw new Error("invalid ciphertext");
  const rawHeader = encodeCbor(header);
  const digest = sha256(SIGNATURE_DOMAIN_V2, rawHeader, enc, ciphertext);
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pinnedBuilderPublicKey)]),
    format: "der",
    type: "spki",
  });
  if (!nodeVerify(null, digest, publicKey, signature)) throw new Error("invalid package signature");
  if (!Buffer.from(bstr(header, 3, 32, "builderKeyId")).equals(bytes(builderKeyId(pinnedBuilderPublicKey), 32, "builderKeyId"))) {
    throw new Error("unpinned builder key");
  }
  validateHeader(header, expected, publicFromPrivate(recipientPrivateKey));
  const plaintextBytes = hpkeOpen(
    recipientPrivateKey,
    enc,
    packageInfoV2(headerForInfo(header)),
    rawHeader,
    ciphertext,
  );
  const plaintext = decodeCanonicalCbor(plaintextBytes);
  const walletMembership = validatePackagePlaintextV2(
    expected.packageType,
    plaintext,
    header,
    expected.content,
  );
  const replayStatus = await expected.replay.claim({
    wallet: expected.wallet,
    packageId: hex(bstr(header, 2, 32, "packageId")),
    sequence: uint(header, 10, "sequence"),
    envelopeDigest: hex(sha256(envelopeBytes)),
  });
  return { header, plaintext, plaintextBytes, walletMembership, replayStatus };
}
