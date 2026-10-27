import assert from "node:assert/strict";
import test from "node:test";
import {
  createGapProver,
  saltBindingWitness,
  credentialWellFormedWitness,
  pseudonymWellFormedWitness,
  type ProverConfig,
} from "../src/index";
import { realPoseidon } from "./wf-poseidon";

const identity = { did: 111111111111111111n, privateSalt: 222222222222222222n };
const ita = 0x1111111111111111111111111111111111111111n;
const regimeHash = 0xaaaabbbbn;
const ikId = 0x1234n;
const gatedContract = 0x5fbdb2315678afecb367f032d93f642f64180aa3n;
// regime 0 under GAP_ATTR_CRED_V3: residency, sanctions, citizenship, reserved.
const attrs: [bigint, bigint, bigint, bigint] = [840n, 0n, 840n, 0n];
const expiresAt = 4000000000n;

/**
 * The session lane already computes all three folds. These circuits exist to let an IK check
 * them WITHOUT the salt, so the one thing that must never drift is the arithmetic itself:
 * if a well-formedness witness disagreed with `createGapProver`, the IK would admit a
 * commitment the session circuit can never open.
 */
async function sessionProver() {
  const crypto = await realPoseidon();
  return {
    crypto,
    prover: createGapProver({
      crypto: crypto as unknown as ProverConfig["crypto"],
    }),
  };
}

test("the salt commitment is the DID registry's, computed once", async () => {
  const { crypto, prover } = await sessionProver();
  const witness = await saltBindingWitness(crypto, identity);
  assert.equal(witness.salt, identity.privateSalt);
  assert.equal(witness.saltCommitment, await prover.saltCommitment(identity));
  assert.equal(witness.saltCommitment, await crypto.h2(identity.privateSalt, 0n));
});

test("the credential leaf a device builds is the leaf the session circuit reopens", async () => {
  const { crypto, prover } = await sessionProver();
  const witness = await credentialWellFormedWitness(crypto, {
    identity,
    ita,
    regimeHash,
    ikId,
    attrs,
    expiresAt,
  });
  assert.equal(
    witness.leaf,
    await prover.credentialCommitment(ita, regimeHash, ikId, attrs, expiresAt, identity),
  );
  assert.equal(witness.attrsHash, await crypto.h4(attrs[0], attrs[1], attrs[2], attrs[3]));
  assert.equal(witness.saltCommitment, await prover.saltCommitment(identity));
  assert.equal(witness.did, identity.did);
  assert.equal(witness.salt, identity.privateSalt);
});

test("the per-contract anchor is the session's pseudonym, and the master anchor is its prefix", async () => {
  const { crypto, prover } = await sessionProver();
  const witness = await pseudonymWellFormedWitness(crypto, {
    identity,
    regimeHash,
    gatedContract,
  });
  assert.equal(witness.pseudonym, await prover.pseudonymFor(regimeHash, gatedContract, identity));
  // master = H2(H2(did, salt), regime), pn2, the fold the per-contract anchor is built ON.
  assert.equal(
    witness.masterPseudonym,
    await crypto.h2(await crypto.h2(identity.did, identity.privateSalt), regimeHash),
  );
  assert.equal(witness.pseudonym, await crypto.h2(witness.masterPseudonym, gatedContract));
});

test("two gated contracts share one master anchor, which is the point of publishing it", async () => {
  const { crypto } = await sessionProver();
  const first = await pseudonymWellFormedWitness(crypto, {
    identity,
    regimeHash,
    gatedContract,
  });
  const second = await pseudonymWellFormedWitness(crypto, {
    identity,
    regimeHash,
    gatedContract: 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512n,
  });
  assert.equal(first.masterPseudonym, second.masterPseudonym);
  assert.notEqual(first.pseudonym, second.pseudonym);
  assert.equal(first.saltCommitment, second.saltCommitment);
});

test("a different salt under the same DID moves every anchor, commitment included", async () => {
  const { crypto } = await sessionProver();
  const mine = await pseudonymWellFormedWitness(crypto, { identity, regimeHash, gatedContract });
  const theirs = await pseudonymWellFormedWitness(crypto, {
    identity: { did: identity.did, privateSalt: identity.privateSalt + 1n },
    regimeHash,
    gatedContract,
  });
  assert.notEqual(mine.saltCommitment, theirs.saltCommitment);
  assert.notEqual(mine.masterPseudonym, theirs.masterPseudonym);
  assert.notEqual(mine.pseudonym, theirs.pseudonym);
});
