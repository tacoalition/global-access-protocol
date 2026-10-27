// Types for the shared GAP v2 offchain crypto module.
//
// `gap_crypto.js` is CommonJS and hand-written; it is required by the joined prover at runtime
// and IMPORTED STATICALLY by the browser session worker, which is bundled. This declaration
// exists for the second caller: a bundler needs a static import, and a static import of an
// untyped `.js` is an implicit `any` that would hide a signature change in the one module
// whose Poseidon parity with the circuit and the on-chain library is a critical invariant.

export const P: bigint;

export function poseidon(): Promise<unknown>;
export function h2(a: unknown, b: unknown): Promise<bigint>;
export function h4(a: unknown, b: unknown, c: unknown, d: unknown): Promise<bigint>;
export function chain(items: unknown[]): Promise<bigint>;
export function toBig(value: unknown): bigint;
export function keccakToField(value: string | bigint): bigint;

export class SparseTree {
  constructor(depth: number);
  init(): Promise<void>;
  indexOf(key: bigint): number;
  set(index: number, value: bigint): void;
  setByKey(key: bigint, value: bigint): void;
  root(): bigint;
  proof(index: number): { siblings: bigint[]; pathIndices: number[] };
}

export class IndexedTree {
  constructor(depth: number);
  init(): Promise<void>;
  predecessorIndex(key: bigint): number;
  insert(key: bigint): Promise<void>;
  remove(key: bigint): Promise<void>;
  root(): bigint;
  lowLeafFor(key: bigint): {
    index: number;
    lowKey: bigint;
    nextKey: bigint;
    siblings: bigint[];
    pathIndices: number[];
  };
}
