import { createRequire } from "node:module";
import { P } from "../src/index";

const require = createRequire(import.meta.url);

/**
 * The REAL Poseidon the circuit uses, circomlibjs, the same build the Identity Keeper's
 * `createPoseidon2` and `circuits/scripts/v2/gap_crypto.js` drive. A well-formedness test that
 * hashed with anything else would pass against its own arithmetic and fail against the circuit.
 */
export interface WfCrypto {
  h2(a: unknown, b: unknown): Promise<bigint>;
  /** Genuine Poseidon(3): the blinded keeper reference, pub[17]. */
  h3(a: unknown, b: unknown, c: unknown): Promise<bigint>;
  /** Genuine Poseidon(4): the per-regime attribute fold. NOT `chain` of four items. */
  h4(a: unknown, b: unknown, c: unknown, d: unknown): Promise<bigint>;
  chain(items: unknown[]): Promise<bigint>;
}

export async function realPoseidon(): Promise<WfCrypto> {
  // circomlibjs ships CJS with no typed surface for buildPoseidon.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { buildPoseidon } = require("circomlibjs") as { buildPoseidon: () => Promise<any> };
  const poseidon = await buildPoseidon();
  const h2 = async (a: unknown, b: unknown): Promise<bigint> => {
    const left = BigInt(a as bigint);
    const right = BigInt(b as bigint);
    if (left < 0n || left >= P || right < 0n || right >= P) {
      throw new Error("poseidon input outside the BN254 field");
    }
    return poseidon.F.toObject(poseidon([left, right]));
  };
  const h3 = async (a: unknown, b: unknown, c: unknown): Promise<bigint> => {
    const values = [a, b, c].map((value) => BigInt(value as bigint));
    if (values.some((value) => value < 0n || value >= P)) {
      throw new Error("poseidon input outside the BN254 field");
    }
    return poseidon.F.toObject(poseidon(values));
  };
  const h4 = async (a: unknown, b: unknown, c: unknown, d: unknown): Promise<bigint> => {
    const values = [a, b, c, d].map((value) => BigInt(value as bigint));
    if (values.some((value) => value < 0n || value >= P)) {
      throw new Error("poseidon input outside the BN254 field");
    }
    return poseidon.F.toObject(poseidon(values));
  };
  return {
    h2,
    h3,
    h4,
    async chain(items) {
      let acc = BigInt(items[0] as bigint);
      for (let i = 1; i < items.length; i += 1) acc = await h2(acc, items[i]);
      return acc;
    },
  };
}
