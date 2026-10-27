// GAP v2, building the three well-formedness witnesses on the holder's device.
//
// Every value here is folded with the SAME injected `crypto` the session lane uses
// (`ProverConfig["crypto"]`), through the same two primitives: `h2` and the left-fold `chain`.
// There is no arithmetic in this file that `createGapProver` does not already perform, 
// `packages/gap-sdk/test/wf-witness.test.ts` asserts each derivation against its session-lane
// counterpart under real Poseidon, because a well-formedness witness that disagreed with the
// session prover would have an IK admit a commitment the session circuit can never open.
//
// The salt enters as a parameter and leaves only as `saltCommitment`, `leaf` and the two
// pseudonym anchors. Nothing here logs, stores or returns it.

import { CRED_TAG } from "./types";
import type {
  CredentialWellFormedWitness,
  PseudonymWellFormedWitness,
  SaltBindingWitness,
} from "./wf-layout";

/** The two fold primitives, injected. Structurally `ProverConfig["crypto"]` minus the tree. */
export interface WfFolds {
  h2(a: unknown, b: unknown): Promise<bigint>;
  /** Genuine Poseidon(4): the per-regime attribute fold. NOT `chain` of four items. */
  h4(a: unknown, b: unknown, c: unknown, d: unknown): Promise<bigint>;
  chain(items: unknown[]): Promise<bigint>;
}

/** The two secrets a client-custody device holds. `privateSalt` never leaves it. */
export interface WfIdentity {
  readonly did: bigint;
  readonly privateSalt: bigint;
}

export interface CredentialWellFormedInput {
  readonly identity: WfIdentity;
  /** The identity anchor (`ita`) the credential is written under. */
  readonly ita: bigint;
  readonly regimeHash: bigint;
  readonly ikId: bigint;
  /** Exactly four attributes per regime: the leaf's `attrsHash` is a Poseidon(4) over them. */
  readonly attrs: readonly [bigint, bigint, bigint, bigint];
  readonly expiresAt: bigint;
}

export interface PseudonymWellFormedInput {
  readonly identity: WfIdentity;
  readonly regimeHash: bigint;
  /** A `DsiFundScopeAnchor` wherever the deployment has one; the token only in the v2 CLI demo. */
  readonly gatedContract: bigint;
}

/** `H2(salt, 0)`, identical to `GapProver.saltCommitment`. */
export async function saltBindingWitness(
  crypto: WfFolds,
  identity: WfIdentity,
): Promise<SaltBindingWitness> {
  return {
    salt: identity.privateSalt,
    saltCommitment: await crypto.h2(identity.privateSalt, 0n),
  };
}

/**
 * The 8-field `GAP_ATTR_CRED_V3` leaf plus the commitment that binds it to the registered salt.
 * The fold is the same `chain([...])` call `GapProver.credentialCommitment` makes, with the same
 * `CRED_TAG`, in the same order.
 */
export async function credentialWellFormedWitness(
  crypto: WfFolds,
  input: CredentialWellFormedInput,
): Promise<CredentialWellFormedWitness> {
  const attrsHash = await crypto.h4(input.attrs[0], input.attrs[1], input.attrs[2], input.attrs[3]);
  const leaf = await crypto.chain([
    CRED_TAG,
    input.ita,
    input.regimeHash,
    input.identity.did,
    attrsHash,
    input.identity.privateSalt,
    input.ikId,
    input.expiresAt,
  ]);
  return {
    salt: input.identity.privateSalt,
    attrs: [input.attrs[0], input.attrs[1], input.attrs[2], input.attrs[3]],
    leaf,
    saltCommitment: await crypto.h2(input.identity.privateSalt, 0n),
    ita: input.ita,
    regimeHash: input.regimeHash,
    did: input.identity.did,
    attrsHash,
    ikId: input.ikId,
    expiresAt: input.expiresAt,
  };
}

/**
 * BOTH pseudonym anchors, from one salt.
 *
 *   masterPseudonym = chain([did, salt, regimeHash]), pn2, the contract-independent name
 *   pseudonym       = h2(masterPseudonym, gatedContract), pn3, what a venue's ORDB flags
 *
 * `pseudonym` is byte-for-byte `GapProver.pseudonymFor(regimeHash, gatedContract, identity)`;
 * the master anchor is the prefix that fold already computes and then discards. Publishing it
 * costs no extra hashing and is what lets an IK recognise one holder across two securities
 * without learning the salt that links them.
 */
export async function pseudonymWellFormedWitness(
  crypto: WfFolds,
  input: PseudonymWellFormedInput,
): Promise<PseudonymWellFormedWitness> {
  const masterPseudonym = await crypto.chain([
    input.identity.did,
    input.identity.privateSalt,
    input.regimeHash,
  ]);
  return {
    salt: input.identity.privateSalt,
    saltCommitment: await crypto.h2(input.identity.privateSalt, 0n),
    did: input.identity.did,
    regimeHash: input.regimeHash,
    gatedContract: input.gatedContract,
    masterPseudonym,
    pseudonym: await crypto.h2(masterPseudonym, input.gatedContract),
  };
}
