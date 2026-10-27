import { assertArtifactPins, verifyConfiguredArtifacts } from "./artifacts";
import { inputFromScenario, inputFromWitness, spendingKeyRootFor } from "./input-builder";
import { LOCAL_CIRCUIT_METADATA, assertCircuitMetadata } from "./metadata";
import { sampleField } from "./random";
import {
  CRED_TAG,
  P,
  type ProverConfig,
  type SessionInput,
  type SessionScenario,
  type WitnessData,
} from "./types";

const asBigInt = (value: string | bigint): bigint => BigInt(value);

export interface FormattedProof {
  pA: [bigint, bigint];
  pB: [[bigint, bigint], [bigint, bigint]];
  pC: [bigint, bigint];
  pub: bigint[];
}

export function assertPublicSignals(
  publicSignals: readonly (string | bigint)[],
  expectedLength = 19,
): bigint[] {
  if (publicSignals.length !== expectedLength) {
    throw new Error(
      `GAP SDK: expected ${expectedLength} public signals, got ${publicSignals.length}`,
    );
  }
  return publicSignals.map((value, index) => {
    const field = asBigInt(value);
    if (field < 0n || field >= P) {
      throw new Error(`GAP SDK: public signal ${index} is outside the BN254 field`);
    }
    return field;
  });
}

/** Format a snarkjs proof into SessionManager calldata. */
export function formatProof(
  // snarkjs does not export a stable proof type.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  proof: any,
  publicSignals: string[],
): FormattedProof {
  const pub = assertPublicSignals(publicSignals);
  return {
    pA: [asBigInt(proof.pi_a[0]), asBigInt(proof.pi_a[1])],
    pB: [
      [asBigInt(proof.pi_b[0][1]), asBigInt(proof.pi_b[0][0])],
      [asBigInt(proof.pi_b[1][1]), asBigInt(proof.pi_b[1][0])],
    ],
    pC: [asBigInt(proof.pi_c[0]), asBigInt(proof.pi_c[1])],
    pub,
  };
}

export interface GapProver {
  credentialCommitment(
    ita: bigint,
    regime: bigint,
    ikId: bigint,
    /** The FOUR attributes of this regime, attrsHash is a genuine Poseidon(4) over them. */
    attrs: readonly [bigint, bigint, bigint, bigint],
    expiresAt: bigint,
    identity: { did: bigint; privateSalt: bigint },
  ): Promise<bigint>;
  pseudonymFor(
    regime0: bigint,
    gatedContract: bigint,
    identity: { did: bigint; privateSalt: bigint },
  ): Promise<bigint>;
  saltCommitment(identity: { privateSalt: bigint }): Promise<bigint>;
  /**
   * A one-wallet spending set's root. The BLIND IS REQUIRED, see `input-builder.ts`: defaulting
   * it to zero rebuilds the old unblinded leaf, whose root was computable from the address alone.
   */
  spendingKeyRootFor(account: bigint, spendingBlind: bigint): Promise<{ root: bigint }>;
  sampleField(): bigint;
  buildSessionInput(scenario: SessionScenario): Promise<SessionInput>;
  buildSessionInputFromWitness(witness: WitnessData): Promise<SessionInput>;
  proveInputServer(input: Record<string, unknown>): Promise<FormattedProof & { provingMs: number }>;
}

export function createGapProver(config: ProverConfig): GapProver {
  const metadata = config.metadata ?? LOCAL_CIRCUIT_METADATA;
  assertCircuitMetadata(metadata);
  let verifiedArtifacts: Promise<void> | undefined;

  const credentialCommitment: GapProver["credentialCommitment"] = async (
    ita,
    regime,
    ikId,
    attrs,
    expiresAt,
    identity,
  ) => {
    const attrsHash = await config.crypto.h4(attrs[0], attrs[1], attrs[2], attrs[3]);
    return config.crypto.chain([
      CRED_TAG,
      ita,
      regime,
      identity.did,
      attrsHash,
      identity.privateSalt,
      ikId,
      expiresAt,
    ]);
  };

  const pseudonymFor: GapProver["pseudonymFor"] = async (
    regime0,
    gatedContract,
    identity,
  ) =>
    config.crypto.h2(
      await config.crypto.h2(
        await config.crypto.h2(identity.did, identity.privateSalt),
        regime0,
      ),
      gatedContract,
    );

  const saltCommitment: GapProver["saltCommitment"] = (identity) =>
    config.crypto.h2(identity.privateSalt, 0n);

  async function proveInputServer(input: Record<string, unknown>) {
    if (!config.groth16 || !config.wasm || !config.zkey) {
      throw new Error("GAP SDK: groth16, wasm, and zkey are required for server proving");
    }
    if (metadata.profile === "base-fund-production" && !config.verificationKey) {
      throw new Error("GAP SDK: production proving requires a verification-key artifact");
    }
    assertArtifactPins(metadata, {
      wasm: config.wasm,
      zkey: config.zkey,
      verificationKey: config.verificationKey,
    });
    verifiedArtifacts ??= verifyConfiguredArtifacts(
      [config.wasm, config.zkey, ...(config.verificationKey ? [config.verificationKey] : [])],
      config.verifyArtifact,
    );
    await verifiedArtifacts;
    const started = Date.now();
    const { proof, publicSignals } = await config.groth16.fullProve(
      input,
      config.wasm.source,
      config.zkey.source,
    );
    return {
      ...formatProof(proof, publicSignals),
      provingMs: Date.now() - started,
    };
  }

  return {
    credentialCommitment,
    pseudonymFor,
    saltCommitment,
    async spendingKeyRootFor(account, spendingBlind) {
      const result = await spendingKeyRootFor(
        config.crypto,
        metadata.depths.spendingKey,
        account,
        spendingBlind,
      );
      return { root: result.root };
    },
    sampleField: () => sampleField(config.randomBytes),
    buildSessionInput: (scenario) => inputFromScenario(config, scenario),
    buildSessionInputFromWitness: (witness) => inputFromWitness(config, witness),
    proveInputServer,
  };
}
