// GAP v2, verifying a client-custody well-formedness proof.
//
// This is the half the Identity Keeper runs. It is deliberately separate from `wf-prover.ts`:
// the verifier needs a verification key and NO proving artifacts, and a module that pulled the
// zkey in would put a 24MB artifact and a witness calculator on the IK's critical path for
// something it never proves.

import type { WfCircuitId } from "./wf-layout";
import { assertWfPublicSignals } from "./wf-layout";

/** snarkjs's Groth16 proof JSON. Structural, because snarkjs exports no stable type. */
export interface WfProofJson {
  readonly pi_a: readonly string[];
  readonly pi_b: readonly (readonly string[])[];
  readonly pi_c: readonly string[];
  readonly protocol?: string;
  readonly curve?: string;
}

export interface WfProof {
  readonly circuit: WfCircuitId;
  readonly proof: WfProofJson;
  readonly publicSignals: readonly string[];
}

export interface WfVerifier {
  // snarkjs has no stable exported TypeScript interface.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  verify(verificationKey: any, publicSignals: readonly string[], proof: any): Promise<boolean>;
}

export interface WfVerifyInput {
  readonly groth16: WfVerifier;
  /** The parsed `*_vkey.json`, whose digest the caller has already checked against its pins. */
  readonly verificationKey: unknown;
  readonly proof: WfProof;
}

/**
 * Verify one well-formedness proof.
 *
 * The layout is asserted BEFORE the pairing check, not after: a proof carrying the wrong number
 * of public signals, or a signal outside the field, is a malformed submission and must be named
 * as one. Handing it to snarkjs instead would surface as a bare `false`, indistinguishable from
 * a forged proof, and the wrong thing to tell an operator.
 *
 * A `false` return means the proof does not verify. It does NOT mean the publics are the ones the
 * IK expects: that comparison is the caller's, against its own records, and
 * `packages/gap-sdk/src/wf-contract.ts` states exactly which fields it covers.
 */
export async function verifyWfProof(input: WfVerifyInput): Promise<boolean> {
  const { circuit, proof, publicSignals } = input.proof;
  assertWfPublicSignals(circuit, publicSignals);
  if (!proof || !Array.isArray(proof.pi_a) || !Array.isArray(proof.pi_c)) {
    throw new Error(`GAP SDK: ${circuit}: proof is not a Groth16 proof`);
  }
  return input.groth16.verify(input.verificationKey, [...publicSignals], proof);
}

/** Parse a verification key that arrived as bytes (the shape a pinned artifact travels in). */
export function parseWfVerificationKey(source: string | Uint8Array): unknown {
  const text = typeof source === "string" ? source : new TextDecoder().decode(source);
  const parsed = JSON.parse(text) as { protocol?: string; curve?: string };
  if (parsed.protocol !== "groth16") {
    throw new Error(`GAP SDK: verification key is not groth16 (${String(parsed.protocol)})`);
  }
  return parsed;
}
