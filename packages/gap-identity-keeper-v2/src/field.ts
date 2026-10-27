import { randomBytes } from "node:crypto";
import { buildPoseidon } from "circomlibjs";
import type { Address, Bytes32, Hex } from "./types";

export const BN254_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const CRED_TAG =
  7398619034839472060957547841361825911550539606183619483712186628328937676175n;
/** keccak256("GAP_SPENDING_BLIND_V2") mod p, blinds the spending-key leaf so the published
 *  `spendingKeyRoot` stops being a preimage of the holder's wallets.
 *  MIRRORS: circuits/src/v2/lib/gap_session.circom, packages/gap-sdk/src/types.ts,
 *  circuits/scripts/v2/prove_session.js. See SPENDING_SET_PRIVACY.md (full stack, not in this repository). */
export const SPENDING_BLIND_TAG =
  20739668207314188630064942382150002554459284316356860011996029219836196127177n;

export function assertBytes(value: string, bytes: number, label: string): asserts value is Hex {
  if (!new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)) {
    throw new Error(`${label} must be exactly ${bytes} bytes`);
  }
}

export function assertField(value: bigint, label: string): void {
  if (value < 0n || value >= BN254_FIELD) throw new Error(`${label} is not a BN254 field element`);
}

export function toBytes32(value: bigint): Bytes32 {
  assertField(value, "value");
  return `0x${value.toString(16).padStart(64, "0")}`;
}

export function fromHex(value: Hex): bigint {
  return BigInt(value);
}

export function addressToField(value: Address): bigint {
  assertBytes(value, 20, "address");
  return BigInt(value);
}

export function sampleField(random: (size: number) => Uint8Array = randomBytes): bigint {
  for (;;) {
    const bytes = random(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new Error("random source must return exactly 32 bytes");
    }
    const candidate = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
    if (candidate > 0n && candidate < BN254_FIELD) return candidate;
  }
}

export interface Poseidon2 {
  hash2(left: bigint, right: bigint): bigint;
  /** Genuine Poseidon(4): the per-regime attribute fold under GAP_ATTR_CRED_V3. NOT a hash2 chain. */
  hash4(a: bigint, b: bigint, c: bigint, d: bigint): bigint;
}

export async function createPoseidon2(): Promise<Poseidon2> {
  const poseidon = await buildPoseidon();
  return {
    hash2(left, right) {
      assertField(left, "left");
      assertField(right, "right");
      return poseidon.F.toObject(poseidon([left, right]));
    },
    hash4(a, b, c, d) {
      const inputs = [a, b, c, d];
      inputs.forEach((value, index) => assertField(value, `attribute ${index}`));
      return poseidon.F.toObject(poseidon(inputs));
    },
  };
}

export function foldHash(hasher: Poseidon2, values: readonly bigint[]): bigint {
  if (values.length < 2) throw new Error("foldHash requires at least two values");
  return values.slice(2).reduce((acc, value) => hasher.hash2(acc, value), hasher.hash2(values[0], values[1]));
}
