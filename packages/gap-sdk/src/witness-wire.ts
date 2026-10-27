// The ONE definition of a session witness on the wire.
//
// It exists because proving MOVED. The Identity Keeper still assembles the witness: it holds
// the subject's salt and owns the spending-wallet set, but the proof is now generated on the
// holder's device, so the assembled witness has to cross an HTTP boundary to get there.
//
// JSON has no bigint, so every field is carried as a decimal string and widened back here.
// Both ends import THIS module (the IK directly; the browser through the bundled session
// runtime built from this same package), so there is no second copy of the format to drift.
//
// Decoding is strict on purpose. This is the only path by which a holder's device is told
// what to prove, and a field that silently decodes to the wrong value produces a proof that
// either fails on chain or, worse, binds something nobody checked. Every field is validated
// for shape and range; nothing is coerced.
//
// WHAT THIS CARRIES. The witness includes `did` and `privateSalt`, because the circuit takes
// them as private input signals and there is no proving without them. That is the honest cost
// of this slice: the IK remains the CUSTODIAN of the salt (it stores it, it issues it, it
// decides who gets one), and the device holds a copy only for the life of one proving
// operation. Moving custody itself is a later slice; nothing here should be read as having
// done that.

import type { Clause, SpendingKeyWitness, WitnessData } from "./types";
import { P } from "./types";

export const WITNESS_WIRE_VERSION = 1;

export interface ClauseWire {
  readonly enabled: number;
  readonly groupId: number;
  readonly attrIndex: number;
  readonly op: number;
  readonly value: string;
}

export interface SpendingKeyWitnessWire {
  readonly root: string;
  readonly siblings: readonly string[];
  readonly pathIndices: readonly number[];
}

export interface WitnessWire {
  readonly version: number;
  readonly did: string;
  readonly privateSalt: string;
  readonly account: string;
  readonly attrs: readonly string[];
  readonly credExpiresAt: readonly string[];
  readonly ikId0: string;
  readonly ikId1: string;
  readonly ita0: string;
  readonly ita1: string;
  readonly regime0: string;
  readonly regime1: string;
  readonly sessionManager: string;
  readonly chainId: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly validUntil: string;
  readonly accountNonce: string;
  readonly gatedContract: string;
  readonly ordbId: string;
  readonly monitorKeyId: string;
  readonly clauses: readonly ClauseWire[];
  readonly didRoot: string;
  readonly credRoot0: string;
  readonly credRoot1: string;
  readonly didSiblings: readonly string[];
  readonly didIndex: number;
  readonly spendingKeyWitness?: SpendingKeyWitnessWire;
  readonly cred0Siblings: readonly string[];
  readonly cred0Index: number;
  readonly cred1Siblings: readonly string[];
  readonly cred1Index: number;
  readonly rdb: {
    readonly root: string;
    readonly lowKey: string;
    readonly nextKey: string;
    readonly siblings: readonly string[];
    readonly index: number;
  };
}

/**
 * Scalars that MUST reduce inside the BN254 field.
 *
 * Every one of these is either a circuit input signal or one of the nineteen public signals,
 * so a value at or above the modulus is not a witness that can be proven at all: it is a
 * misconfigured deployment, and naming it here is how that surfaces as a sentence rather than
 * as an unexplained witness-calculation failure inside a worker.
 */
const FIELD_SCALARS = [
  "did", "privateSalt", "account", "ikId0", "ikId1", "ita0", "ita1", "regime0", "regime1",
  "sessionManager", "chainId", "validUntil", "accountNonce",
  "gatedContract", "ordbId", "monitorKeyId", "didRoot", "credRoot0", "credRoot1",
] as const;

/**
 * Scalars that are uint256 WORDS, not field elements.
 *
 * `policyId` is a bytes32 chosen by the policy registry and is routinely larger than the
 * BN254 modulus; it never enters the circuit. It reaches the prover only as authenticated
 * associated data in the transaction-monitor envelope, where it is a 32-byte word. Field
 * checking it would reject perfectly valid deployments: this lane's own `holderPolicyId` is
 * one of them.
 */
const WORD_SCALARS = ["policyId", "policyVersion"] as const;

const SCALARS = [...FIELD_SCALARS, ...WORD_SCALARS] as const;

type ScalarField = (typeof SCALARS)[number];

const TWO_256 = 1n << 256n;

const DECIMAL = /^(0|[1-9][0-9]*)$/;

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`GAP witness wire: ${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * A field element, as text.
 *
 * Range-checked against the BN254 modulus rather than merely parsed: a value at or above `P`
 * is not a witness the circuit can consume, and catching it here names the field instead of
 * surfacing later as an unexplained witness-calculation failure inside the worker.
 */
function scalar(raw: unknown, name: string, limit: bigint = P): bigint {
  if (typeof raw !== "string" || !DECIMAL.test(raw)) {
    throw new Error(`GAP witness wire: ${name} must be a decimal string`);
  }
  const value = BigInt(raw);
  if (value >= limit) {
    throw new Error(
      limit === P
        ? `GAP witness wire: ${name} is outside the BN254 field`
        : `GAP witness wire: ${name} does not fit in 32 bytes`,
    );
  }
  return value;
}

function field(source: Record<string, unknown>, name: string): bigint {
  return scalar(source[name], name);
}

function fieldArray(source: Record<string, unknown>, name: string, length?: number): bigint[] {
  const raw = source[name];
  if (!Array.isArray(raw)) throw new Error(`GAP witness wire: ${name} must be an array`);
  if (length !== undefined && raw.length !== length) {
    throw new Error(`GAP witness wire: ${name} must have ${length} entries, got ${raw.length}`);
  }
  return raw.map((entry, position) => scalar(entry, `${name}[${position}]`));
}

function index(source: Record<string, unknown>, name: string): number {
  const raw = source[name];
  if (!Number.isSafeInteger(raw) || (raw as number) < 0) {
    throw new Error(`GAP witness wire: ${name} must be a non-negative integer`);
  }
  return raw as number;
}

function bits(source: Record<string, unknown>, name: string): number[] {
  const raw = source[name];
  if (!Array.isArray(raw)) throw new Error(`GAP witness wire: ${name} must be an array`);
  return raw.map((value) => {
    if (value !== 0 && value !== 1) {
      throw new Error(`GAP witness wire: ${name} entries must be 0 or 1`);
    }
    return value;
  });
}

function decodeClauses(source: Record<string, unknown>): Clause[] {
  const raw = source.clauses;
  // Six is the circuit's shape (MAX_CLAUSES), not a policy choice: `assertWitness` refuses
  // anything else, and a wire that carried five would fail deep inside the input builder
  // instead of here.
  if (!Array.isArray(raw) || raw.length !== 6) {
    throw new Error("GAP witness wire: clauses must be an array of six");
  }
  return raw.map((entry, position) => {
    const clause = record(entry, `clauses[${position}]`);
    return {
      enabled: index(clause, "enabled"),
      groupId: index(clause, "groupId"),
      attrIndex: index(clause, "attrIndex"),
      op: index(clause, "op"),
      value: field(clause, "value"),
    };
  });
}

function decodeSpendingWitness(source: Record<string, unknown>): SpendingKeyWitness | undefined {
  if (source.spendingKeyWitness === undefined) return undefined;
  const witness = record(source.spendingKeyWitness, "spendingKeyWitness");
  const siblings = fieldArray(witness, "siblings");
  const pathIndices = bits(witness, "pathIndices");
  if (siblings.length !== pathIndices.length) {
    throw new Error("GAP witness wire: spending-key siblings and path indices must pair up");
  }
  return { root: field(witness, "root"), siblings, pathIndices };
}

export function encodeWitnessWire(witness: WitnessData): WitnessWire {
  const scalars = Object.fromEntries(
    SCALARS.map((name) => [name, witness[name as ScalarField].toString()]),
  ) as Record<ScalarField, string>;
  return {
    version: WITNESS_WIRE_VERSION,
    ...scalars,
    attrs: witness.attrs.map(String),
    credExpiresAt: witness.credExpiresAt.map(String),
    clauses: witness.clauses.map((clause) => ({ ...clause, value: clause.value.toString() })),
    didSiblings: witness.didSiblings.map(String),
    didIndex: witness.didIndex,
    ...(witness.spendingKeyWitness
      ? {
        spendingKeyWitness: {
          root: witness.spendingKeyWitness.root.toString(),
          siblings: witness.spendingKeyWitness.siblings.map(String),
          pathIndices: [...witness.spendingKeyWitness.pathIndices],
        },
      }
      : {}),
    cred0Siblings: witness.cred0Siblings.map(String),
    cred0Index: witness.cred0Index,
    cred1Siblings: witness.cred1Siblings.map(String),
    cred1Index: witness.cred1Index,
    rdb: {
      root: witness.rdb.root.toString(),
      lowKey: witness.rdb.lowKey.toString(),
      nextKey: witness.rdb.nextKey.toString(),
      siblings: witness.rdb.siblings.map(String),
      index: witness.rdb.index,
    },
  };
}

export function decodeWitnessWire(value: unknown): WitnessData {
  const wire = record(value, "witness");
  if (wire.version !== WITNESS_WIRE_VERSION) {
    // A device proving against a format the assembler no longer speaks would build a witness
    // nobody checked. Refuse rather than guess which fields still mean what they used to.
    throw new Error(`GAP witness wire: unsupported version ${String(wire.version)}`);
  }
  const scalars = Object.fromEntries([
    ...FIELD_SCALARS.map((name) => [name, field(wire, name)]),
    ...WORD_SCALARS.map((name) => [name, scalar(wire[name], name, TWO_256)]),
  ]) as Record<ScalarField, bigint>;
  const attrs = fieldArray(wire, "attrs", 8) as [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
  const credExpiresAt = fieldArray(wire, "credExpiresAt", 2) as [bigint, bigint];
  const spendingKeyWitness = decodeSpendingWitness(wire);
  const rdb = record(wire.rdb, "rdb");
  return {
    ...scalars,
    attrs,
    credExpiresAt,
    clauses: decodeClauses(wire),
    didSiblings: fieldArray(wire, "didSiblings"),
    didIndex: index(wire, "didIndex"),
    ...(spendingKeyWitness ? { spendingKeyWitness } : {}),
    cred0Siblings: fieldArray(wire, "cred0Siblings"),
    cred0Index: index(wire, "cred0Index"),
    cred1Siblings: fieldArray(wire, "cred1Siblings"),
    cred1Index: index(wire, "cred1Index"),
    rdb: {
      root: field(rdb, "root"),
      lowKey: field(rdb, "lowKey"),
      nextKey: field(rdb, "nextKey"),
      siblings: fieldArray(rdb, "siblings"),
      index: index(rdb, "index"),
    },
  };
}
