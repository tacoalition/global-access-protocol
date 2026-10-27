// snarkjs ships no type declarations. This describes only the groth16 surface the CLI touches
// (both provers import `groth16` and hand it to `createGapProver`). Keep it narrow: widening this
// to `any` would silently un-type every proving call site in the package.
declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string | Uint8Array,
      zkeyFile: string | Uint8Array,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    verify(
      verificationKey: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
    exportSolidityCallData(proof: unknown, publicSignals: string[]): Promise<string>;
  };
}
