export const PUBLIC_SIGNAL_NAMES = [
  "account",
  "chainId",
  "sessionManager",
  "clausesHash",
  "validUntil",
  "accountNonce",
  "didRoot",
  "ita0",
  "regimeHash0",
  "credRoot0",
  "ita1",
  "regimeHash1",
  "credRoot1",
  "ordbId",
  "riskRoot",
  "gatedContract",
  "pseudonymCommitment",
  "ikRefCommitment",
  "monitorKeyId",
] as const;

export interface CircuitMetadata {
  profile: "gap-v2-local" | "base-fund-local" | "base-fund-production";
  publicSignals: typeof PUBLIC_SIGNAL_NAMES;
  depths: {
    did: number;
    spendingKey: number;
    credential: number;
    risk: number;
  };
  artifactDigests?: {
    r1cs?: `0x${string}`;
    wasm?: `0x${string}`;
    zkey?: `0x${string}`;
    verificationKey?: `0x${string}`;
  };
}

export const LOCAL_CIRCUIT_METADATA: CircuitMetadata = {
  profile: "gap-v2-local",
  publicSignals: PUBLIC_SIGNAL_NAMES,
  depths: { did: 16, spendingKey: 4, credential: 16, risk: 14 },
};

export const BASE_FUND_CIRCUIT_METADATA: CircuitMetadata = {
  profile: "base-fund-production",
  publicSignals: PUBLIC_SIGNAL_NAMES,
  depths: { did: 16, spendingKey: 8, credential: 16, risk: 20 },
};

/**
 * Joined Anvil profile used by the integration acceptance stack.
 * It preserves the reviewed Base Fund eight-level wallet-set boundary while
 * keeping the smaller local-only DID, credential, and risk trees.
 */
export const BASE_FUND_LOCAL_CIRCUIT_METADATA: CircuitMetadata = {
  profile: "base-fund-local",
  publicSignals: PUBLIC_SIGNAL_NAMES,
  depths: { did: 16, spendingKey: 8, credential: 16, risk: 14 },
};

export function assertCircuitMetadata(metadata: CircuitMetadata): void {
  if (metadata.publicSignals.length !== 19) {
    throw new Error(`GAP SDK: expected 19 public signals, got ${metadata.publicSignals.length}`);
  }
  for (let i = 0; i < PUBLIC_SIGNAL_NAMES.length; i += 1) {
    if (metadata.publicSignals[i] !== PUBLIC_SIGNAL_NAMES[i]) {
      throw new Error(
        `GAP SDK: public signal ${i} must be ${PUBLIC_SIGNAL_NAMES[i]}, got ${metadata.publicSignals[i]}`,
      );
    }
  }
  if (metadata.depths.credential !== metadata.depths.did) {
    throw new Error("GAP SDK: DID and credential depths must match");
  }
  for (const [name, depth] of Object.entries(metadata.depths)) {
    if (!Number.isSafeInteger(depth) || depth <= 0 || depth > 31) {
      throw new Error(`GAP SDK: invalid ${name} depth ${depth}`);
    }
  }
}
