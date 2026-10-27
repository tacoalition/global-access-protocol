// GAP v2, proving client-custody well-formedness on the holder's device.
//
// Three separate Groth16 circuits, three separate artifact sets, one small statement each. They
// share nothing with the session lane but the folds: `createGapProver` is untouched, the 19-slot
// layout is untouched, and a well-formedness proof is never SessionManager calldata, so nothing
// here formats one.

import { verifyArtifactBytes } from "./artifacts";
import type { ArtifactReference } from "./types";
import {
  WF_CIRCUIT_IDS,
  assertWfPublicSignals,
  wfCircuitInput,
  type WfCircuitId,
  type WfWitness,
} from "./wf-layout";
import { parseWfVerificationKey, verifyWfProof, type WfProof } from "./wf-verify";

export interface WfArtifactSet {
  readonly wasm: ArtifactReference;
  readonly zkey: ArtifactReference;
  readonly verificationKey: ArtifactReference;
}

export interface WfProverConfig {
  // snarkjs has no stable exported TypeScript interface.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly groth16: any;
  readonly artifacts: Readonly<Record<WfCircuitId, WfArtifactSet>>;
  /**
   * Injected because path and URL artifacts cannot be hashed from bytes the SDK holds. Defaults
   * to the in-memory check; a Node consumer passes one that reads the file. Required for path
   * artifacts, exactly as `verifyArtifactBytes` says.
   */
  readonly verifyArtifact?: (artifact: ArtifactReference) => Promise<void>;
  /** Reads a path/URL artifact. Needed only by `verify`, to load a verification key. */
  readonly readArtifact?: (artifact: ArtifactReference) => Promise<Uint8Array>;
}

export interface WfProofResult extends WfProof {
  readonly provingMs: number;
}

export interface WfProver {
  prove<Id extends WfCircuitId>(circuit: Id, witness: WfWitness<Id>): Promise<WfProofResult>;
  verify(proof: WfProof): Promise<boolean>;
}

/**
 * A prover over the three well-formedness circuits.
 *
 * ARTIFACTS ARE CHECKED BEFORE THEY PROVE, once per circuit and memoised. A zkey that does not
 * match its pin is not a slow path, it is a different circuit: proofs made under it verify
 * against a verification key nobody pinned, which is precisely the substitution the pins exist to
 * catch. The digests come from `circuits/build/wf/pins.json`, which the DEVELOPMENT build script
 * writes, see `scripts/v2/build-wf.sh` for why those keys prove nothing outside a test.
 */
export function createWfProver(config: WfProverConfig): WfProver {
  const verifyArtifact = config.verifyArtifact ?? verifyArtifactBytes;
  const checked = new Map<WfCircuitId, Promise<void>>();
  const keys = new Map<WfCircuitId, Promise<unknown>>();

  for (const id of WF_CIRCUIT_IDS) {
    if (!config.artifacts[id]) throw new Error(`GAP SDK: no artifacts configured for ${id}`);
  }

  const ensureProvingArtifacts = (circuit: WfCircuitId): Promise<void> => {
    let pending = checked.get(circuit);
    if (!pending) {
      const set = config.artifacts[circuit];
      pending = Promise.all([verifyArtifact(set.wasm), verifyArtifact(set.zkey)]).then(() => undefined);
      checked.set(circuit, pending);
    }
    return pending;
  };

  const verificationKey = (circuit: WfCircuitId): Promise<unknown> => {
    let pending = keys.get(circuit);
    if (!pending) {
      const artifact = config.artifacts[circuit].verificationKey;
      pending = verifyArtifact(artifact).then(async () => {
        if (artifact.source instanceof Uint8Array) return parseWfVerificationKey(artifact.source);
        if (!config.readArtifact) {
          throw new Error("GAP SDK: a path verification key requires an injected readArtifact");
        }
        return parseWfVerificationKey(await config.readArtifact(artifact));
      });
      keys.set(circuit, pending);
    }
    return pending;
  };

  return {
    async prove(circuit, witness) {
      const set = config.artifacts[circuit];
      const input = wfCircuitInput(circuit, witness);
      await ensureProvingArtifacts(circuit);
      const started = Date.now();
      const { proof, publicSignals } = await config.groth16.fullProve(
        input,
        set.wasm.source,
        set.zkey.source,
      );
      assertWfPublicSignals(circuit, publicSignals);
      return { circuit, proof, publicSignals, provingMs: Date.now() - started };
    },
    async verify(proof) {
      return verifyWfProof({
        groth16: config.groth16,
        verificationKey: await verificationKey(proof.circuit),
        proof,
      });
    },
  };
}
