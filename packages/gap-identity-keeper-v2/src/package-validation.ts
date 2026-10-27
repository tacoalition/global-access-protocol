import { requireMap, type CborValue } from "./cbor";
import {
  BN254_FIELD,
  addressToField,
  toBytes32,
  type Poseidon2,
} from "./field";
import {
  computeCredentialLeaf,
  computeOneLeafRoot,
  computeSaltCommitment,
} from "./credential-builder";
import type { Address, Bytes32 } from "./types";

export interface ConfirmedPackageSlot {
  readonly anchor: Address;
  readonly regimeHash: Bytes32;
  readonly ikId: Bytes32;
  readonly credentialRevision: bigint;
  readonly commitment: Bytes32;
  readonly expiresAt: bigint;
  readonly treeIndex: number;
  readonly issueTxHash: Bytes32;
  readonly issueBlockHash: Bytes32;
  readonly canonical: boolean;
  readonly revoked: boolean;
}

export type PackageContentExpectations =
  | { readonly packageType: 1; readonly hasher: Poseidon2 }
  | {
      readonly packageType: 2;
      readonly hasher: Poseidon2;
      readonly did: Bytes32;
      readonly privateSalt: Bytes32;
      readonly policyId: Bytes32;
      readonly slots: readonly [ConfirmedPackageSlot, ConfirmedPackageSlot];
    };

function uint(value: CborValue | undefined, bits: number, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(bits)) throw new Error(`${label} must be uint${bits}`);
  return value;
}

function bstr(value: CborValue | undefined, length: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error(`${label} must be ${length} bytes`);
  return value;
}

function field(value: CborValue | undefined, label: string): Uint8Array {
  const bytes = bstr(value, 32, label);
  if (BigInt(`0x${Buffer.from(bytes).toString("hex")}`) >= BN254_FIELD) throw new Error(`${label} is not a BN254 field`);
  return bytes;
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

function hex(bytes: Uint8Array): Bytes32 {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function equalHex(left: string, right: string, label: string): void {
  if (left.toLowerCase() !== right.toLowerCase()) throw new Error(`${label} mismatch`);
}

function array(value: CborValue | undefined, length: number, label: string): readonly CborValue[] {
  if (!Array.isArray(value) || value.length !== length) throw new Error(`${label} must contain exactly ${length} entries`);
  return value;
}

function validateSlot(value: CborValue): ReadonlyMap<number, CborValue> {
  const slot = requireMap(value, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  bstr(slot.get(0), 20, "slot ITA");
  field(slot.get(1), "slot regime hash");
  field(slot.get(2), "slot IK ID");
  uint(slot.get(3), 64, "slot expiry");
  if (uint(slot.get(4), 64, "slot credential revision") === 0n) throw new Error("slot credential revision must be nonzero");
  field(slot.get(5), "slot commitment");
  uint(slot.get(6), 16, "slot tree index");
  bstr(slot.get(7), 32, "slot issue transaction hash");
  bstr(slot.get(8), 32, "slot issue block hash");
  return slot;
}

function validateSeedContent(
  seed: ReadonlyMap<number, CborValue>,
  hasher: Poseidon2,
): void {
  const did = BigInt(hex(field(seed.get(0), "seed DID")));
  const privateSalt = BigInt(hex(field(seed.get(1), "seed private salt")));
  const saltCommitment = toBytes32(computeSaltCommitment(hasher, privateSalt));
  equalHex(saltCommitment, hex(field(seed.get(2), "seed salt commitment")), "seed salt commitment");

  const accountBytes = bstr(seed.get(4), 20, "seed bound account");
  const account = `0x${Buffer.from(accountBytes).toString("hex")}` as Address;
  const spendingLeaf = hasher.hash2(addressToField(account), 0n);
  const spendingRoot = computeOneLeafRoot(
    hasher,
    spendingLeaf,
    Number(addressToField(account) & 0xffn),
    8,
  );
  equalHex(toBytes32(spendingRoot), hex(field(seed.get(5), "seed spending root")), "seed spending root");
  if (Number(did & 0xffffn) !== Number(uint(seed.get(6), 16, "reserved DID index"))) {
    throw new Error("reserved DID index does not match the DID");
  }
}

function validateIssuedSlot(
  slot: ReadonlyMap<number, CborValue>,
  confirmed: ConfirmedPackageSlot,
  attributes: readonly [bigint, bigint, bigint, bigint],
  did: Bytes32,
  privateSalt: Bytes32,
  hasher: Poseidon2,
): void {
  if (!confirmed.canonical || confirmed.revoked) {
    throw new Error("issued slot is not backed by a canonical active record");
  }
  const anchor = `0x${Buffer.from(bstr(slot.get(0), 20, "slot ITA")).toString("hex")}` as Address;
  const regimeHash = hex(field(slot.get(1), "slot regime hash"));
  const ikId = hex(field(slot.get(2), "slot IK ID"));
  const expiresAt = uint(slot.get(3), 64, "slot expiry");
  const revision = uint(slot.get(4), 64, "slot credential revision");
  const commitment = hex(field(slot.get(5), "slot commitment"));
  const treeIndex = Number(uint(slot.get(6), 16, "slot tree index"));
  const issueTxHash = hex(bstr(slot.get(7), 32, "slot issue transaction hash"));
  const issueBlockHash = hex(bstr(slot.get(8), 32, "slot issue block hash"));

  equalHex(anchor, confirmed.anchor, "slot anchor");
  equalHex(regimeHash, confirmed.regimeHash, "slot regime");
  equalHex(ikId, confirmed.ikId, "slot IK ID");
  if (revision !== confirmed.credentialRevision) throw new Error("slot credential revision mismatch");
  if (expiresAt !== confirmed.expiresAt) throw new Error("slot expiry mismatch");
  if (treeIndex !== confirmed.treeIndex) throw new Error("slot tree index mismatch");
  equalHex(issueTxHash, confirmed.issueTxHash, "slot issue transaction");
  equalHex(issueBlockHash, confirmed.issueBlockHash, "slot issue block");
  equalHex(commitment, confirmed.commitment, "slot confirmed commitment");
  const recomputed = computeCredentialLeaf(hasher, {
    chainId: 84532,
    anchor,
    regimeHash,
    did,
    ikId,
    attributes,
    privateSalt,
    expiresAt,
  });
  equalHex(commitment, recomputed, "slot recomputed commitment");
}

export function validatePackagePlaintext(
  packageType: 1 | 2,
  value: CborValue,
  header: ReadonlyMap<number, CborValue>,
  expected: PackageContentExpectations,
): void {
  if (packageType !== expected.packageType) throw new Error("package content expectation mismatch");
  if (packageType === 1) {
    const seed = requireMap(value, [0, 1, 2, 3, 4, 5, 6, 7]);
    field(seed.get(0), "seed DID");
    field(seed.get(1), "seed private salt");
    field(seed.get(2), "seed salt commitment");
    if (uint(seed.get(3), 32, "spending rule version") !== 1n) throw new Error("unsupported spending rule version");
    const account = bstr(seed.get(4), 20, "seed bound account");
    field(seed.get(5), "seed spending root");
    uint(seed.get(6), 16, "reserved DID index");
    const keys = array(seed.get(7), 1, "governance keys");
    const governance = bstr(keys[0], 20, "governance key");
    if (!same(account, governance) || !same(account, bstr(header.get(5), 20, "header wallet"))) throw new Error("seed wallet/governance binding mismatch");
    validateSeedContent(seed, expected.hasher);
    return;
  }
  if (expected.packageType !== 2) throw new Error("issued package content expectation mismatch");
  const issued = requireMap(value, [0, 1, 2, 3, 4, 5, 6]);
  const did = hex(field(issued.get(0), "issued DID"));
  const privateSalt = hex(field(issued.get(1), "issued private salt"));
  equalHex(did, expected.did, "issued DID");
  equalHex(privateSalt, expected.privateSalt, "issued private salt");
  const rawAttributes = array(issued.get(2), 8, "issued attributes");
  const attributes = rawAttributes.map((attribute) => uint(attribute, 64, "issued attribute"));
  // The demo lane's fixed shape under GAP_ATTR_CRED_V3: each regime carries [1,1,0,0], so the full
  // array is [1,1,0,0,1,1,0,0]. The reserved slots are checked to be ZERO rather than ignored: a
  // reserved index that may carry anything is not reserved.
  const EXPECTED_DEMO_ATTRS = [1n, 1n, 0n, 0n, 1n, 1n, 0n, 0n];
  if (attributes.some((attribute, i) => attribute !== EXPECTED_DEMO_ATTRS[i])) {
    throw new Error("issued demo attributes must be exactly [1,1,0,0,1,1,0,0]");
  }
  const rawSlots = array(issued.get(3), 2, "issued slots");
  const slots = rawSlots.map(validateSlot);
  const policyId = hex(field(issued.get(4), "policy ID"));
  equalHex(policyId, expected.policyId, "issued policy ID");
  if (uint(issued.get(5), 32, "holder policy version") !== uint(header.get(9), 32, "header holder policy version")) throw new Error("plaintext/header holder policy mismatch");
  if (uint(issued.get(6), 32, "level policy revision") !== uint(header.get(14), 32, "header level policy revision")) throw new Error("plaintext/header level policy mismatch");
  if (expected.slots[0].anchor.toLowerCase() === expected.slots[1].anchor.toLowerCase()) {
    throw new Error("issued package requires distinct identity and fund anchors");
  }
  validateIssuedSlot(slots[0], expected.slots[0], [attributes[0], attributes[1], attributes[2], attributes[3]], did, privateSalt, expected.hasher);
  validateIssuedSlot(slots[1], expected.slots[1], [attributes[4], attributes[5], attributes[6], attributes[7]], did, privateSalt, expected.hasher);
}
