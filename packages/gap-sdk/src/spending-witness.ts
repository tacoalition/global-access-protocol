import { P, type SpendingKeyWitness } from "./types";

export const GAP_SPENDING_WALLET_SET_V2_PROFILE = "GAP_SPENDING_WALLET_SET_V2";
// 3: the spending leaf gained its blind (SPENDING_SET_PRIVACY.md (full stack, not in this repository)). A schema-2 package
// describes an UNBLINDED tree, whose root is a preimage of the holder's wallets, so it is refused
// rather than opened. MIRRORS: gap-identity-keeper-v2 SPENDING_WALLET_SET_SCHEMA_VERSION and the
// wire check in its package-content-v2.ts, bound by scripts/platform/depth-parity.test.mjs.
export const GAP_SPENDING_WALLET_SET_V2_SCHEMA = 3;
export const GAP_SPENDING_WALLET_SET_V2_DEPTH = 8;

/** Dependency-free structural boundary matching the V2 IK package opener. */
export interface PackagedSpendingWalletWitnessV2 {
  readonly profile: typeof GAP_SPENDING_WALLET_SET_V2_PROFILE;
  readonly schemaVersion: typeof GAP_SPENDING_WALLET_SET_V2_SCHEMA;
  readonly root: string;
  readonly revision: bigint;
  readonly assignedSlot: number;
  readonly siblings: readonly string[];
  readonly pathIndices: readonly number[];
}

function field(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`GAP SDK: ${label} must be exactly 32 bytes`);
  }
  const parsed = BigInt(value);
  if (parsed >= P) throw new Error(`GAP SDK: ${label} is outside the BN254 field`);
  return parsed;
}

export function spendingKeyWitnessFromV2Package(
  input: unknown,
): SpendingKeyWitness {
  if (!input || typeof input !== "object") {
    throw new Error("GAP SDK: packaged spending witness must be an object");
  }
  const packaged = input as Partial<Record<keyof PackagedSpendingWalletWitnessV2, unknown>>;
  if (packaged.profile !== GAP_SPENDING_WALLET_SET_V2_PROFILE) {
    throw new Error("GAP SDK: packaged spending witness has the wrong profile");
  }
  if (packaged.schemaVersion !== GAP_SPENDING_WALLET_SET_V2_SCHEMA) {
    throw new Error("GAP SDK: packaged spending witness has the wrong schema");
  }
  if (
    typeof packaged.revision !== "bigint" ||
    packaged.revision <= 0n ||
    packaged.revision >= 1n << 64n
  ) {
    throw new Error("GAP SDK: packaged spending witness revision must be nonzero uint64");
  }
  if (
    !Array.isArray(packaged.siblings) ||
    packaged.siblings.length !== GAP_SPENDING_WALLET_SET_V2_DEPTH
  ) {
    throw new Error("GAP SDK: packaged spending witness requires eight siblings");
  }
  if (
    !Array.isArray(packaged.pathIndices) ||
    packaged.pathIndices.length !== GAP_SPENDING_WALLET_SET_V2_DEPTH
  ) {
    throw new Error("GAP SDK: packaged spending witness requires eight path indices");
  }
  if (packaged.pathIndices.some((path) => path !== 0 && path !== 1)) {
    throw new Error("GAP SDK: packaged spending witness path indices must be binary");
  }
  if (
    !Number.isSafeInteger(packaged.assignedSlot) ||
    (packaged.assignedSlot as number) < 0 ||
    (packaged.assignedSlot as number) > 255
  ) {
    throw new Error("GAP SDK: packaged spending witness assigned slot must be uint8");
  }
  const assignedSlot = packaged.assignedSlot as number;
  const pathsMatch = packaged.pathIndices.every(
    (path, level) => path === ((assignedSlot >> level) & 1),
  );
  if (!pathsMatch) {
    throw new Error("GAP SDK: packaged spending witness path does not match assigned slot");
  }
  return {
    root: field(packaged.root, "spending root"),
    siblings: packaged.siblings.map(
      (sibling, index) => field(sibling, `spending sibling ${index}`),
    ),
    pathIndices: [...packaged.pathIndices] as number[],
  };
}
