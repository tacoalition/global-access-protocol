import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";
import { cborMap, decodeCanonicalCbor, encodeCbor, requireMap, type CborValue } from "./cbor";
import { generateX25519RawKeyPair, hpkeOpen, hpkeSeal } from "./hpke";
import { assertBytes } from "./field";
import type { Address, Bytes32 } from "./types";
import {
  validatePackagePlaintext,
  type PackageContentExpectations,
} from "./package-validation";
import type { PackageReplayPort } from "./package-replay";

export const PACKAGE_PROFILE = "DSI_CREDENTIAL_PACKAGE_HPKE_V1";
export const PACKAGE_SCHEMA_REVISION = 1;
const SIGNATURE_DOMAIN = Buffer.from("DSI_CREDENTIAL_PACKAGE_SIG_V1", "ascii");

export type PackageType = 1 | 2;

export interface PackageHeader {
  readonly packageType: PackageType;
  readonly packageId: Bytes32;
  readonly builderKeyId: Bytes32;
  readonly walletBindingDigest: Bytes32;
  readonly boundWallet: Address;
  readonly chainId: 84532;
  readonly didRegistry: Address;
  readonly holderPolicyVersion: number;
  readonly builderSequence: bigint;
  readonly createdAt: bigint;
  readonly expiresAt: bigint;
  readonly recipientKeyDigest: Bytes32;
  readonly levelPolicyRevision: number;
}

export interface SeedPlaintext {
  readonly did: Bytes32;
  readonly privateSalt: Bytes32;
  readonly saltCommitment: Bytes32;
  readonly boundAccount: Address;
  readonly expectedSpendingRoot: Bytes32;
  readonly reservedDidIndex: number;
  readonly governanceKeys: readonly [Address];
}

export interface IssuedSlot {
  readonly ita: Address;
  readonly regimeHash: Bytes32;
  readonly ikId: Bytes32;
  readonly expiresAt: bigint;
  readonly slotCredentialRevision: bigint;
  readonly commitment: Bytes32;
  readonly treeIndex: number;
  readonly issueTxHash: Bytes32;
  readonly issueBlockHash: Bytes32;
}

export interface IssuedPlaintext {
  readonly did: Bytes32;
  readonly privateSalt: Bytes32;
  /** All EIGHT attributes: regime 0 is [0..3], regime 1 is [4..7]. */
  readonly attributes: readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
  readonly slots: readonly [IssuedSlot, IssuedSlot];
  readonly policyId: Bytes32;
  readonly holderPolicyVersion: number;
  readonly levelPolicyRevision: number;
}

export interface PackageSigner {
  readonly rawPublicKey: Uint8Array;
  signDigest(digest: Uint8Array): Promise<Uint8Array>;
}

export interface PackageExpectations {
  readonly packageType: PackageType;
  readonly wallet: Address;
  readonly walletBindingDigest: Bytes32;
  readonly didRegistry: Address;
  readonly minimumSequence: bigint;
  readonly now: bigint;
  readonly holderPolicyVersion: number;
  readonly levelPolicyRevision: number;
  readonly content: PackageContentExpectations;
  readonly replay: PackageReplayPort;
}

function bytes(hex: string, length: number, label: string): Uint8Array {
  assertBytes(hex, length, label);
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

function assertUint(value: bigint | number, bits: number, label: string): void {
  const bigintValue = BigInt(value);
  if (bigintValue < 0n || bigintValue >= 1n << BigInt(bits)) throw new Error(`${label} exceeds uint${bits}`);
}

export function builderKeyId(rawPublicKey: Uint8Array): Bytes32 {
  if (rawPublicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return hex(sha256(rawPublicKey));
}

export function recipientKeyDigest(rawPublicKey: Uint8Array): Bytes32 {
  if (rawPublicKey.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return hex(sha256(rawPublicKey));
}

export function encodeHeader(header: PackageHeader): Uint8Array {
  assertBytes(header.packageId, 32, "packageId");
  assertBytes(header.builderKeyId, 32, "builderKeyId");
  assertBytes(header.walletBindingDigest, 32, "walletBindingDigest");
  assertBytes(header.boundWallet, 20, "boundWallet");
  assertBytes(header.didRegistry, 20, "didRegistry");
  assertBytes(header.recipientKeyDigest, 32, "recipientKeyDigest");
  assertUint(header.holderPolicyVersion, 32, "holderPolicyVersion");
  assertUint(header.builderSequence, 64, "builderSequence");
  assertUint(header.createdAt, 64, "createdAt");
  assertUint(header.expiresAt, 64, "expiresAt");
  assertUint(header.levelPolicyRevision, 32, "levelPolicyRevision");
  if (header.expiresAt < header.createdAt || header.expiresAt - header.createdAt > 600n) {
    throw new Error("package delivery expiry must be within ten minutes");
  }
  return encodeCbor(cborMap([
    [0, 1], [1, header.packageType], [2, bytes(header.packageId, 32, "packageId")],
    [3, bytes(header.builderKeyId, 32, "builderKeyId")],
    [4, bytes(header.walletBindingDigest, 32, "walletBindingDigest")],
    [5, bytes(header.boundWallet, 20, "boundWallet")], [6, header.chainId],
    [7, bytes(header.didRegistry, 20, "didRegistry")], [8, PACKAGE_SCHEMA_REVISION],
    [9, header.holderPolicyVersion], [10, header.builderSequence], [11, header.createdAt],
    [12, header.expiresAt], [13, bytes(header.recipientKeyDigest, 32, "recipientKeyDigest")],
    [14, header.levelPolicyRevision],
  ]));
}

export function packageInfo(header: PackageHeader): Uint8Array {
  return sha256(encodeCbor([
    PACKAGE_PROFILE,
    header.packageType,
    header.chainId,
    bytes(header.didRegistry, 20, "didRegistry"),
    PACKAGE_SCHEMA_REVISION,
  ]));
}

export function encodeSeedPlaintext(value: SeedPlaintext): Uint8Array {
  if (value.reservedDidIndex < 0 || value.reservedDidIndex > 0xffff) throw new Error("reservedDidIndex exceeds uint16");
  if (value.governanceKeys.length !== 1 || value.governanceKeys[0].toLowerCase() !== value.boundAccount.toLowerCase()) {
    throw new Error("seed package requires exactly the bound account as governance key");
  }
  return encodeCbor(cborMap([
    [0, bytes(value.did, 32, "did")], [1, bytes(value.privateSalt, 32, "privateSalt")],
    [2, bytes(value.saltCommitment, 32, "saltCommitment")], [3, 1],
    [4, bytes(value.boundAccount, 20, "boundAccount")],
    [5, bytes(value.expectedSpendingRoot, 32, "expectedSpendingRoot")],
    [6, value.reservedDidIndex], [7, [bytes(value.governanceKeys[0], 20, "governanceKey")]],
  ]));
}

function slotMap(slot: IssuedSlot): ReadonlyMap<number, CborValue> {
  assertUint(slot.expiresAt, 64, "slot.expiresAt");
  assertUint(slot.slotCredentialRevision, 64, "slotCredentialRevision");
  if (slot.treeIndex < 0 || slot.treeIndex > 0xffff) throw new Error("treeIndex exceeds uint16");
  return cborMap([
    [0, bytes(slot.ita, 20, "ita")], [1, bytes(slot.regimeHash, 32, "regimeHash")],
    [2, bytes(slot.ikId, 32, "ikId")], [3, slot.expiresAt], [4, slot.slotCredentialRevision],
    [5, bytes(slot.commitment, 32, "commitment")], [6, slot.treeIndex],
    [7, bytes(slot.issueTxHash, 32, "issueTxHash")], [8, bytes(slot.issueBlockHash, 32, "issueBlockHash")],
  ]);
}

export function encodeIssuedPlaintext(value: IssuedPlaintext): Uint8Array {
  if (value.attributes.some((attribute) => attribute < 0n || attribute > 0xffffffffffffffffn)) {
    throw new Error("attribute exceeds uint64");
  }
  return encodeCbor(cborMap([
    [0, bytes(value.did, 32, "did")], [1, bytes(value.privateSalt, 32, "privateSalt")],
    [2, value.attributes], [3, [slotMap(value.slots[0]), slotMap(value.slots[1])]],
    [4, bytes(value.policyId, 32, "policyId")], [5, value.holderPolicyVersion],
    [6, value.levelPolicyRevision],
  ]));
}

export async function sealPackage(
  header: PackageHeader,
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  signer: PackageSigner,
  ephemeralPrivateKey?: Uint8Array,
): Promise<Uint8Array> {
  if (header.builderKeyId !== builderKeyId(signer.rawPublicKey)) throw new Error("builder key ID mismatch");
  if (header.recipientKeyDigest !== recipientKeyDigest(recipientPublicKey)) throw new Error("recipient key digest mismatch");
  const canonicalHeader = encodeHeader(header);
  const sealed = hpkeSeal(recipientPublicKey, packageInfo(header), canonicalHeader, plaintext, ephemeralPrivateKey);
  const digest = sha256(SIGNATURE_DOMAIN, canonicalHeader, sealed.enc, sealed.ciphertext);
  const signature = await signer.signDigest(digest);
  if (signature.length !== 64) throw new Error("Ed25519 signature must be 64 bytes");
  return encodeCbor(cborMap([[0, decodeCanonicalCbor(canonicalHeader)], [1, sealed.enc], [2, sealed.ciphertext], [3, signature]]));
}

function mapUint(map: ReadonlyMap<number, CborValue>, key: number, label: string): bigint {
  const value = map.get(key);
  if (typeof value !== "bigint") throw new Error(`${label} must be a CBOR uint`);
  return value;
}

function mapBytes(map: ReadonlyMap<number, CborValue>, key: number, length: number, label: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error(`${label} has wrong length`);
  return value;
}

function validateDecodedHeader(map: ReadonlyMap<number, CborValue>, expected: PackageExpectations, recipientPublic: Uint8Array): void {
  if (mapUint(map, 0, "profileVersion") !== 1n || mapUint(map, 1, "packageType") !== BigInt(expected.packageType)) throw new Error("package profile/type mismatch");
  if (mapUint(map, 6, "chainId") !== 84532n || mapUint(map, 8, "schemaRevision") !== 1n) throw new Error("chain/schema mismatch");
  if (mapUint(map, 9, "holderPolicyVersion") !== BigInt(expected.holderPolicyVersion)) throw new Error("holder policy mismatch");
  if (mapUint(map, 14, "levelPolicyRevision") !== BigInt(expected.levelPolicyRevision)) throw new Error("level policy mismatch");
  if (mapUint(map, 10, "sequence") < expected.minimumSequence) throw new Error("stale builder sequence");
  const createdAt = mapUint(map, 11, "createdAt");
  const expiresAt = mapUint(map, 12, "expiresAt");
  if (createdAt > expected.now || expiresAt < expected.now || expiresAt < createdAt || expiresAt - createdAt > 600n) throw new Error("package is not currently deliverable");
  mapBytes(map, 2, 32, "package ID");
  const checks: Array<[number, string, number]> = [[4, expected.walletBindingDigest, 32], [5, expected.wallet, 20], [7, expected.didRegistry, 20]];
  for (const [key, value, length] of checks) if (!Buffer.from(mapBytes(map, key, length, "header field")).equals(bytes(value, length, "expected field"))) throw new Error("package binding mismatch");
  if (!Buffer.from(mapBytes(map, 13, 32, "recipient digest")).equals(bytes(recipientKeyDigest(recipientPublic), 32, "recipient digest"))) throw new Error("wrong recipient key");
}

export function nodeEd25519Signer(privateKey: KeyObject): PackageSigner {
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  const rawPublicKey = Buffer.from(publicDer).subarray(-32);
  return { rawPublicKey, async signDigest(digest) { return nodeSign(null, Buffer.from(digest), privateKey); } };
}

export async function openPackage(
  envelopeBytes: Uint8Array,
  recipientPrivateKey: Uint8Array,
  pinnedBuilderPublicKey: Uint8Array,
  expected: PackageExpectations,
): Promise<{
  header: ReadonlyMap<number, CborValue>;
  plaintext: CborValue;
  plaintextBytes: Uint8Array;
  replayStatus: "ACCEPTED" | "DUPLICATE";
}> {
  const envelope = requireMap(decodeCanonicalCbor(envelopeBytes), [0, 1, 2, 3]);
  const header = requireMap(envelope.get(0)!, Array.from({ length: 15 }, (_, index) => index));
  const enc = mapBytes(envelope, 1, 32, "HPKE enc");
  const ciphertext = envelope.get(2);
  const signature = mapBytes(envelope, 3, 64, "signature");
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 16) throw new Error("invalid ciphertext");
  const rawHeader = encodeCbor(header);
  const digest = sha256(SIGNATURE_DOMAIN, rawHeader, enc, ciphertext);
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pinnedBuilderPublicKey)]), format: "der", type: "spki" });
  if (!nodeVerify(null, digest, publicKey, signature)) throw new Error("invalid package signature");
  if (!Buffer.from(mapBytes(header, 3, 32, "builderKeyId")).equals(bytes(builderKeyId(pinnedBuilderPublicKey), 32, "builderKeyId"))) throw new Error("unpinned builder key");
  const recipientPublic = generatePublicFromPrivate(recipientPrivateKey);
  validateDecodedHeader(header, expected, recipientPublic);
  const decodedHeader = decodeHeaderForInfo(header);
  const plaintextBytes = hpkeOpen(recipientPrivateKey, enc, packageInfo(decodedHeader), rawHeader, ciphertext);
  const plaintext = decodeCanonicalCbor(plaintextBytes);
  validatePackagePlaintext(expected.packageType, plaintext, header, expected.content);
  const replayStatus = await expected.replay.claim({
    wallet: expected.wallet,
    packageId: hex(mapBytes(header, 2, 32, "packageId")),
    sequence: mapUint(header, 10, "sequence"),
    envelopeDigest: hex(sha256(envelopeBytes)),
  });
  return { header, plaintext, plaintextBytes, replayStatus };
}

function generatePublicFromPrivate(privateKey: Uint8Array): Uint8Array {
  const prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  const privateObject = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(privateKey)]), format: "der", type: "pkcs8" });
  const key = createPublicKey(privateObject);
  return Buffer.from(key.export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
}

function decodeHeaderForInfo(map: ReadonlyMap<number, CborValue>): PackageHeader {
  return {
    packageType: Number(mapUint(map, 1, "packageType")) as PackageType,
    packageId: hex(mapBytes(map, 2, 32, "packageId")), builderKeyId: hex(mapBytes(map, 3, 32, "builderKeyId")),
    walletBindingDigest: hex(mapBytes(map, 4, 32, "bindingDigest")), boundWallet: hex(mapBytes(map, 5, 20, "wallet")),
    chainId: 84532, didRegistry: hex(mapBytes(map, 7, 20, "didRegistry")),
    holderPolicyVersion: Number(mapUint(map, 9, "holderPolicyVersion")), builderSequence: mapUint(map, 10, "sequence"),
    createdAt: mapUint(map, 11, "createdAt"), expiresAt: mapUint(map, 12, "expiresAt"),
    recipientKeyDigest: hex(mapBytes(map, 13, 32, "recipientDigest")), levelPolicyRevision: Number(mapUint(map, 14, "levelRevision")),
  };
}

export { generateX25519RawKeyPair };
