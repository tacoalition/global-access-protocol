// GAP v2, client-custody WELL-FORMEDNESS layouts.
//
// Three small circuits, three DIFFERENT public-signal layouts. None of them is the session
// circuit's 19-slot layout and none of them may be validated with `assertPublicSignals`, whose
// default length is 19: a helper that silently accepted any length is how a layout drifts.
// Every count here is mirrored in exactly two other places and checked against both, 
// `circuits/src/v2/wf_*.circom` (the `{public [...]}` list) and `scripts/v2/build-wf.sh` (the
// pinned table), by `packages/gap-sdk/test/wf-circuits.test.ts`.

import { P } from "./types";

export type WfCircuitId = "saltBinding" | "credentialWellFormed" | "pseudonymWellFormed";

export const WF_CIRCUIT_IDS = [
  "saltBinding",
  "credentialWellFormed",
  "pseudonymWellFormed",
] as const satisfies readonly WfCircuitId[];

export interface WfCircuitLayout {
  readonly id: WfCircuitId;
  /** The compiled artifact's base name: the key under `circuits/build/wf/pins.json`. */
  readonly circuit: string;
  /** Repo-relative path to the main wrapper whose public list this mirrors. */
  readonly main: string;
  /** Public signals, in witness order. snarkjs returns them in exactly this order. */
  readonly publicSignals: readonly string[];
  /** Private witnesses the device supplies. `salt` is in every one of them and public in none. */
  readonly privateInputs: readonly string[];
}

export const WF_CIRCUITS = {
  saltBinding: {
    id: "saltBinding",
    circuit: "wf_salt_binding",
    main: "circuits/src/v2/wf_salt_binding.circom",
    publicSignals: ["saltCommitment"],
    privateInputs: ["salt"],
  },
  credentialWellFormed: {
    id: "credentialWellFormed",
    circuit: "wf_cred",
    main: "circuits/src/v2/wf_cred.circom",
    // Eight publics for the eight-field GAP_ATTR_CRED_V3 leaf: the tag is a circuit constant,
    // the salt appears only as its commitment, and the attributes only as attrsHash.
    publicSignals: [
      "leaf",
      "saltCommitment",
      "ita",
      "regimeHash",
      "did",
      "attrsHash",
      "ikId",
      "expiresAt",
    ],
    privateInputs: ["salt", "attrs"],
  },
  pseudonymWellFormed: {
    id: "pseudonymWellFormed",
    circuit: "wf_pseudonym",
    main: "circuits/src/v2/wf_pseudonym.circom",
    // Two anchors from one committed salt: `pseudonym` is what a venue's ORDB flags,
    // `masterPseudonym` is the contract-independent prefix it is built on.
    publicSignals: [
      "saltCommitment",
      "did",
      "regimeHash",
      "gatedContract",
      "masterPseudonym",
      "pseudonym",
    ],
    privateInputs: ["salt"],
  },
} as const satisfies Record<WfCircuitId, WfCircuitLayout>;

export interface SaltBindingWitness {
  readonly salt: bigint;
  readonly saltCommitment: bigint;
}

export interface CredentialWellFormedWitness {
  readonly salt: bigint;
  readonly attrs: readonly [bigint, bigint, bigint, bigint];
  readonly leaf: bigint;
  readonly saltCommitment: bigint;
  readonly ita: bigint;
  readonly regimeHash: bigint;
  readonly did: bigint;
  readonly attrsHash: bigint;
  readonly ikId: bigint;
  readonly expiresAt: bigint;
}

export interface PseudonymWellFormedWitness {
  readonly salt: bigint;
  readonly saltCommitment: bigint;
  readonly did: bigint;
  readonly regimeHash: bigint;
  readonly gatedContract: bigint;
  readonly masterPseudonym: bigint;
  readonly pseudonym: bigint;
}

export interface WfWitnessOf {
  readonly saltBinding: SaltBindingWitness;
  readonly credentialWellFormed: CredentialWellFormedWitness;
  readonly pseudonymWellFormed: PseudonymWellFormedWitness;
}

export type WfWitness<Id extends WfCircuitId> = WfWitnessOf[Id];

function field(value: unknown, label: string): bigint {
  const asField = typeof value === "bigint" ? value : BigInt(value as string);
  if (asField < 0n || asField >= P) {
    throw new Error(`GAP SDK: ${label} is outside the BN254 field`);
  }
  return asField;
}

/**
 * Validate a proof's public signals against the ONE layout that circuit has.
 *
 * Length is checked by circuit, not against a shared constant, and each slot is named in the
 * failure so an operator reading a refusal knows which value was wrong rather than which index.
 */
export function assertWfPublicSignals(
  circuit: WfCircuitId,
  publicSignals: readonly (string | bigint)[],
): bigint[] {
  const layout = WF_CIRCUITS[circuit];
  if (publicSignals.length !== layout.publicSignals.length) {
    throw new Error(
      `GAP SDK: ${circuit}: expected ${layout.publicSignals.length} public signals, got ${publicSignals.length}`,
    );
  }
  return publicSignals.map((value, index) =>
    field(value, `public signal ${index} (${layout.publicSignals[index]})`),
  );
}

/** Public signals as a named record. An IK compares fields it knows, never positions. */
export function decodeWfPublicSignals(
  circuit: WfCircuitId,
  publicSignals: readonly (string | bigint)[],
): Record<string, bigint> {
  const values = assertWfPublicSignals(circuit, publicSignals);
  const layout = WF_CIRCUITS[circuit];
  const decoded: Record<string, bigint> = {};
  layout.publicSignals.forEach((name, index) => {
    decoded[name] = values[index];
  });
  return decoded;
}

/**
 * A witness as circom input JSON. Keys are the circuit's signal names verbatim, so a rename in
 * the .circom that is not mirrored here fails at witness generation rather than proving something
 * else. Values are decimal strings, snarkjs accepts bigints, but strings survive the JSON
 * round trip a device-to-prover hop may make.
 */
export function wfCircuitInput<Id extends WfCircuitId>(
  circuit: Id,
  witness: WfWitness<Id>,
): Record<string, string | string[]> {
  const layout = WF_CIRCUITS[circuit];
  const source = witness as unknown as Record<string, bigint | readonly bigint[]>;
  const input: Record<string, string | string[]> = {};
  for (const name of [...layout.privateInputs, ...layout.publicSignals]) {
    const value = source[name];
    if (value === undefined) throw new Error(`GAP SDK: ${circuit}: witness is missing ${name}`);
    input[name] = Array.isArray(value)
      ? value.map((entry, index) => field(entry, `${name}[${index}]`).toString())
      : field(value, name).toString();
  }
  return input;
}
