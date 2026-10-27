import { cborMap, encodeCbor, requireMap, type CborValue } from "./cbor";
import { computeSaltCommitment } from "./credential-builder";
import {
  assertStableGovernanceControllers,
  sameControllerSet,
} from "./governance-v2";
import type {
  IssuedPlaintextV2,
  PackageContentExpectationsV2,
  PackagedSpendingWalletWitnessV2,
  SeedPlaintextV2,
} from "./package-types-v2";
import { encodeIssuedPlaintext, type IssuedSlot } from "./package-profile";
import { validatePackagePlaintext } from "./package-validation";
import {
  BN254_FIELD,
  addressToField,
  toBytes32,
} from "./field";
import {
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
  assertSpendingWalletMembership,
} from "./spending-wallet-set";
import type { Address, Bytes32 } from "./types";

function bytes(hex: string, length: number, label: string): Uint8Array {
  if (!new RegExp(`^0x[0-9a-fA-F]{${length * 2}}$`).test(hex)) {
    throw new Error(`${label} must be ${length} bytes`);
  }
  return Buffer.from(hex.slice(2), "hex");
}

function bstr(value: CborValue | undefined, length: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${label} must be ${length} bytes`);
  }
  return value;
}

function uint(value: CborValue | undefined, bits: number, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(bits)) {
    throw new Error(`${label} must be uint${bits}`);
  }
  return value;
}

function array(value: CborValue | undefined, length: number, label: string): readonly CborValue[] {
  if (!Array.isArray(value) || value.length !== length) {
    throw new Error(`${label} must contain exactly ${length} entries`);
  }
  return value;
}

function controllerArray(value: CborValue | undefined): readonly CborValue[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 5) {
    throw new Error("governance controllers must contain 1..5 entries");
  }
  return value;
}

function hex(value: Uint8Array): Bytes32 {
  return `0x${Buffer.from(value).toString("hex")}`;
}

function field(value: CborValue | undefined, label: string): Uint8Array {
  const encoded = bstr(value, 32, label);
  if (BigInt(hex(encoded)) >= BN254_FIELD) throw new Error(`${label} is not a BN254 field`);
  return encoded;
}

function slotMap(slot: IssuedSlot): ReadonlyMap<number, CborValue> {
  return cborMap([
    [0, bytes(slot.ita, 20, "ita")], [1, bytes(slot.regimeHash, 32, "regimeHash")],
    [2, bytes(slot.ikId, 32, "ikId")], [3, slot.expiresAt],
    [4, slot.slotCredentialRevision], [5, bytes(slot.commitment, 32, "commitment")],
    [6, slot.treeIndex], [7, bytes(slot.issueTxHash, 32, "issueTxHash")],
    [8, bytes(slot.issueBlockHash, 32, "issueBlockHash")],
  ]);
}

function membershipMap(
  value: PackagedSpendingWalletWitnessV2,
): ReadonlyMap<number, CborValue> {
  if (
    value.profile !== GAP_SPENDING_WALLET_SET_V2 ||
    value.schemaVersion !== SPENDING_WALLET_SET_SCHEMA_VERSION
  ) {
    throw new Error("unsupported V2 spending wallet profile/schema");
  }
  if (value.siblings.length !== 8 || value.pathIndices.length !== 8) {
    throw new Error("V2 package requires an eight-level spending wallet proof");
  }
  if (value.revision <= 0n || value.revision >= 1n << 64n) {
    throw new Error("V2 wallet-set revision must be nonzero uint64");
  }
  if (!Number.isSafeInteger(value.assignedSlot) || value.assignedSlot < 0 || value.assignedSlot > 255) {
    throw new Error("V2 assigned slot must be uint8");
  }
  if (value.pathIndices.some((path) => path !== 0 && path !== 1)) {
    throw new Error("V2 spending wallet path must be binary");
  }
  return cborMap([
    [0, value.profile], [1, value.schemaVersion], [2, bytes(value.root, 32, "root")],
    [3, value.revision], [4, value.assignedSlot],
    [5, value.siblings.map((sibling) => bytes(sibling, 32, "sibling"))],
    [6, value.pathIndices],
  ]);
}

export function encodeSeedPlaintextV2(value: SeedPlaintextV2): Uint8Array {
  assertStableGovernanceControllers(value.governanceControllers, [value.boundAccount]);
  if (!Number.isSafeInteger(value.reservedDidIndex) || value.reservedDidIndex < 0 || value.reservedDidIndex > 0xffff) {
    throw new Error("reservedDidIndex exceeds uint16");
  }
  return encodeCbor(cborMap([
    [0, bytes(value.did, 32, "did")], [1, bytes(value.privateSalt, 32, "privateSalt")],
    [2, bytes(value.saltCommitment, 32, "saltCommitment")], [3, 2],
    [4, bytes(value.boundAccount, 20, "boundAccount")],
    [5, membershipMap(value.walletMembership)], [6, value.reservedDidIndex],
    [7, value.governanceControllers.map((controller) => bytes(controller, 20, "controller"))],
  ]));
}

export function encodeIssuedPlaintextV2(value: IssuedPlaintextV2): Uint8Array {
  encodeIssuedPlaintext(value);
  return encodeCbor(cborMap([
    [0, bytes(value.did, 32, "did")], [1, bytes(value.privateSalt, 32, "privateSalt")],
    [2, value.attributes], [3, [slotMap(value.slots[0]), slotMap(value.slots[1])]],
    [4, bytes(value.policyId, 32, "policyId")], [5, value.holderPolicyVersion],
    [6, value.levelPolicyRevision], [7, membershipMap(value.walletMembership)],
  ]));
}

function decodedMembership(
  value: CborValue | undefined,
  boundWallet: Address,
  expected: PackageContentExpectationsV2,
): PackagedSpendingWalletWitnessV2 {
  const map = requireMap(value!, [0, 1, 2, 3, 4, 5, 6]);
  if (map.get(0) !== GAP_SPENDING_WALLET_SET_V2) throw new Error("wallet profile mismatch");
  if (uint(map.get(1), 8, "wallet schema") !== 3n) throw new Error("wallet schema mismatch");
  const root = hex(field(map.get(2), "wallet root"));
  const revision = uint(map.get(3), 64, "wallet-set revision");
  const slot = Number(uint(map.get(4), 8, "assigned slot"));
  const siblings = array(map.get(5), 8, "wallet siblings").map((item) => hex(field(item, "wallet sibling")));
  const pathIndices = array(map.get(6), 8, "wallet path").map((item) => Number(uint(item, 1, "wallet path bit")));
  assertSpendingWalletMembership(expected.hasher, {
    account: boundWallet,
    slot,
    leaf: toBytes32(
      expected.hasher.hash2(addressToField(boundWallet), BigInt(expected.expectedSpendingBlind)),
    ),
    root,
    siblings,
    pathIndices,
  }, BigInt(expected.expectedSpendingBlind));
  if (root.toLowerCase() !== expected.expectedSpendingRoot.toLowerCase()) {
    throw new Error("wallet-set root mismatch");
  }
  if (revision !== expected.walletSetRevision) throw new Error("wallet-set revision mismatch");
  return {
    profile: GAP_SPENDING_WALLET_SET_V2,
    schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
    root,
    revision,
    assignedSlot: slot,
    siblings,
    pathIndices,
  };
}

export function validatePackagePlaintextV2(
  packageType: 1 | 2,
  value: CborValue,
  header: ReadonlyMap<number, CborValue>,
  expected: PackageContentExpectationsV2,
): PackagedSpendingWalletWitnessV2 {
  if (packageType !== expected.packageType) throw new Error("V2 package content expectation mismatch");
  const boundWallet = hex(bstr(header.get(5), 20, "header wallet")) as Address;
  if (packageType === 1 && expected.packageType === 1) {
    const seed = requireMap(value, [0, 1, 2, 3, 4, 5, 6, 7]);
    const did = BigInt(hex(field(seed.get(0), "seed DID")));
    const privateSalt = BigInt(hex(field(seed.get(1), "seed private salt")));
    const saltCommitment = toBytes32(computeSaltCommitment(expected.hasher, privateSalt));
    if (saltCommitment.toLowerCase() !== hex(field(seed.get(2), "salt commitment")).toLowerCase()) {
      throw new Error("seed salt commitment mismatch");
    }
    if (uint(seed.get(3), 8, "spending rule version") !== 2n) throw new Error("spending rule mismatch");
    if (!Buffer.from(bstr(seed.get(4), 20, "bound account")).equals(bytes(boundWallet, 20, "header wallet"))) {
      throw new Error("seed/header wallet mismatch");
    }
    const membership = decodedMembership(seed.get(5), boundWallet, expected);
    if (Number(did & 0xffffn) !== Number(uint(seed.get(6), 16, "DID index"))) throw new Error("DID index mismatch");
    const controllers = controllerArray(seed.get(7)).map((item) => hex(bstr(item, 20, "controller")) as Address);
    assertStableGovernanceControllers(controllers, [boundWallet]);
    if (!sameControllerSet(controllers, expected.governanceControllers)) throw new Error("governance controllers mismatch");
    return membership;
  }
  if (packageType !== 2 || expected.packageType !== 2) throw new Error("issued V2 expectation mismatch");
  const issued = requireMap(value, [0, 1, 2, 3, 4, 5, 6, 7]);
  const membership = decodedMembership(issued.get(7), boundWallet, expected);
  const v1Shape = cborMap(Array.from({ length: 7 }, (_, key) => [key, issued.get(key)!] as const));
  validatePackagePlaintext(2, v1Shape, header, { ...expected, packageType: 2 });
  return membership;
}
