/**
 * WITNESS-LEVEL TESTS FOR THE SESSION CIRCUIT.
 *
 * Until this file, nothing tested the circuit. The Foundry suites exercise the contracts, but every
 * one injects a `MockVerifier` returning `true` unconditionally: they prove what the SessionManager
 * does with an ACCEPTED proof, not what the circuit accepts. The sole exception was
 * `expiryConstraintChecks` in `prove_session.js`: one constraint, regime 0's expiry, run only when
 * someone regenerates fixtures. The rest of the soundness argument rested on reading the circom.
 *
 * Witness satisfaction IS constraint satisfaction, so computing a witness for a mutated input
 * decides satisfiability without a Groth16 proof. The baseline is the committed fixture: the exact
 * input behind `contracts/test/fixtures/v2/proof.json`, which drives a real proof through the
 * deployed verifier, so these tests and that fixture cannot disagree about what a session is.
 *
 * Two details decide whether this file is worth anything. A FRESH calculator per case: the instance
 * accumulates error text across calls, so a reused one reports the PREVIOUS case's failing template
 * and every claim about the reason becomes a lie (found here: a mutated `ikRefCommitment` was
 * blamed on cred1's Merkle path). And asserting WHICH constraint rejected it, since a test that
 * accepts any error passes when the input is malformed for an unrelated reason; expected lines are
 * resolved from the circom at runtime, so editing the circuit moves the assertion with it.
 */
import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const WASM = path.join(ROOT, "circuits/build/v2/session_js/session.wasm");
const CALC = path.join(ROOT, "circuits/build/v2/session_js/witness_calculator.js");
const CIRCOM = path.join(ROOT, "circuits/src/v2/lib/gap_session.circom");
const POLICY = path.join(ROOT, "circuits/src/v2/lib/policy.circom");
const FIXTURE = path.join(ROOT, "contracts/test/fixtures/v2/scenario.json");

// Depths mirror session.circom. A wrong value here cannot pass silently: the reconstruction guards
// below rebuild the committed roots, and a bad depth changes every one of them.
const CRED_DEPTH = 16, RDB_DEPTH = 14;
// keccak256("GAP_ATTR_CRED_V3") mod P, must equal the circuit's CRED_TAG and GapLib.credTag.
const CRED_TAG = 7398619034839472060957547841361825911550539606183619483712186628328937676175n;

let gc, builder, wasmCode, base;
const sources = new Map();
const B = (x) => BigInt(x);

before(() => {
  // `circuits/build/` is gitignored, so these artifacts exist only after a build. FAIL rather than
  // skip: a skipped circuit suite reports green and is indistinguishable from a passing one, which
  // is the exact failure mode this file was written to end.
  assert.ok(fs.existsSync(WASM), `missing ${WASM}\n  run: make build`);
  gc = require(path.join(ROOT, "circuits/scripts/v2/gap_crypto.js"));
  builder = require(CALC);
  wasmCode = fs.readFileSync(WASM);
  base = JSON.parse(fs.readFileSync(FIXTURE, "utf8")).input;
  for (const f of [CIRCOM, POLICY]) sources.set(f, fs.readFileSync(f, "utf8").split("\n"));
});

/** The 1-based line of a constraint statement, so assertions survive edits to the circuit. */
function constraintLine(needle, file) {
  const hits = sources.get(file).map((l, i) => (l.includes(needle) ? i + 1 : 0)).filter(Boolean);
  assert.equal(hits.length, 1, `"${needle}" must appear on exactly one line of ${path.basename(file)}`);
  return hits[0];
}

async function witness(input) {
  const calc = await builder(wasmCode); // FRESH, see the header
  return calc.calculateWitness(input, 1);
}
/** The input must be UNSATISFIABLE, and specifically at the constraint on `needle`'s line. */
async function assertRejectedBy(input, needle, where = { file: CIRCOM, template: "GapSession" }) {
  const line = constraintLine(needle, where.file);
  let err;
  try {
    await witness(input);
  } catch (e) {
    err = String(e.message || e);
  }
  assert.ok(err, `expected UNSAT but a witness was produced; "${needle}" does not constrain this`);
  assert.match(
    err.replace(/\n/g, " | "),
    new RegExp(`${where.template}_\\d+ line: ${line}\\b`),
    `rejected, but not by "${needle}" (line ${line}), so this passes for the wrong reason:\n${err}`,
  );
}

async function assertAccepted(input) {
  assert.ok((await witness(input)).length > 0);
}

const bump = (k) => ({ ...base, [k]: (B(base[k]) + 1n).toString() });
const bumpAt = (k, i) => ({ ...base, [k]: base[k].map((v, j) => (j === i ? (B(v) + 1n).toString() : v)) });

// Changing an attribute also changes the credential leaf, so a bare mutation is always rejected by
// the Merkle check and the predicate is never reached. These helpers re-issue the credential: 
// what an adversary with a cooperating Identity Keeper would have.
async function credLeaf({ ita, regime, attrs4, ikId, expiresAt }) {
  const attrsHash = await gc.h4(attrs4[0], attrs4[1], attrs4[2], attrs4[3]);
  return gc.chain([CRED_TAG, ita, regime, B(base.did), attrsHash, B(base.privateSalt), ikId, expiresAt]);
}

async function credTree(leaf) {
  const t = new gc.SparseTree(CRED_DEPTH);
  await t.init();
  t.setByKey(B(base.did), leaf);
  const p = t.proof(t.indexOf(B(base.did)));
  return { root: t.root(), siblings: p.siblings.map(String), pathIndices: p.pathIndices.map(String) };
}
const regime0Cred = (attrs, expiresAt = B(base.cred0ExpiresAt)) =>
  credLeaf({ ita: B(base.ita0), regime: B(base.regimeHash0), attrs4: attrs.slice(0, 4), ikId: B(base.ikId0), expiresAt });
const regime1Cred = (attrs, expiresAt) =>
  credLeaf({ ita: B(base.ita1), regime: B(base.regimeHash1), attrs4: attrs.slice(4, 8), ikId: B(base.ikId1), expiresAt });
async function withRegime0(attrs, expiresAt) {
  const t = await credTree(await regime0Cred(attrs, expiresAt));
  return { ...base, attrs: attrs.map(String), credRoot0: t.root.toString(),
    cred0Siblings: t.siblings, cred0PathIndices: t.pathIndices,
    ...(expiresAt === undefined ? {} : { cred0ExpiresAt: expiresAt.toString() }) };
}

async function withRegime1Expiry(expiresAt) {
  const t = await credTree(await regime1Cred(base.attrs.map(B), expiresAt));
  return { ...base, cred1ExpiresAt: expiresAt.toString(), credRoot1: t.root.toString(),
    cred1Siblings: t.siblings, cred1PathIndices: t.pathIndices };
}
async function pseudonym() {
  const pn1 = await gc.h2(B(base.did), B(base.privateSalt));
  return gc.h2(await gc.h2(pn1, B(base.regimeHash0)), B(base.gatedContract));
}
describe("the committed fixture is a satisfying witness", () => {
  test("positive control, without this every rejection below is meaningless", async () => {
    await assertAccepted(base);
  });
  // GUARD. The cases below re-derive a credential or the risk tree. If a formula here drifted from
  // the circuit, they would be rejected for the wrong reason and still look green.
  test("the derivations these tests rebuild reproduce the committed roots", async () => {
    const t0 = await credTree(await regime0Cred(base.attrs.map(B)));
    assert.equal(t0.root.toString(), base.credRoot0, "regime-0 credential reconstruction drifted");
    const t1 = await credTree(await regime1Cred(base.attrs.map(B), B(base.cred1ExpiresAt)));
    assert.equal(t1.root.toString(), base.credRoot1, "regime-1 credential reconstruction drifted");
    const pn = await pseudonym();
    const { pseudonym: committed } = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
    assert.equal(pn.toString(), committed, "pseudonym fold drifted from the circuit");
  });
});

describe("a holder cannot borrow someone else's identity or wallet", () => {
  const cases = [
    ["a different DID", () => bump("did"), "didMember.root <== didRoot"],
    ["a different private salt", () => bump("privateSalt"), "didMember.root <== didRoot"],
    ["a substituted spending-set root", () => bump("spendingKeyRoot"), "didMember.root <== didRoot"],
    ["a forged DID path", () => bumpAt("didSiblings", 0), "didMember.root <== didRoot"],
    // THE SOUNDNESS PROPERTY THE DESIGN RESTS ON: a session is for a wallet the holder proved is in
    // their own spending set, so a stranger's address cannot be substituted.
    ["a wallet outside the holder's spending set",
      () => ({ ...base, account: "1390849295786071768276380950238675083608645509734" }),
      "skMember.root <== spendingKeyRoot"],
    ["a forged spending-set path", () => bumpAt("skSiblings", 0), "skMember.root <== spendingKeyRoot"],
  ];
  for (const [label, mutate, needle] of cases) {
    test(label, async () => assertRejectedBy(mutate(), needle));
  }
});

describe("a holder cannot invent or re-point a credential", () => {
  const cases = [
    ["an attribute the issuer never attested", () => bumpAt("attrs", 0), "cred0Member.root <== credRoot0"],
    ["a different identity keeper on regime 0", () => bump("ikId0"), "cred0Member.root <== credRoot0"],
    ["a forged regime-0 path", () => bumpAt("cred0Siblings", 0), "cred0Member.root <== credRoot0"],
    ["a stale regime-0 credential root", () => bump("credRoot0"), "cred0Member.root <== credRoot0"],
    ["another anchor's regime 1", () => bump("ita1"), "cred1Member.root <== credRoot1"],
    ["another regime hash on regime 1", () => bump("regimeHash1"), "cred1Member.root <== credRoot1"],
    ["a different identity keeper on regime 1", () => bump("ikId1"), "cred1Member.root <== credRoot1"],
    ["a stale regime-1 credential root", () => bump("credRoot1"), "cred1Member.root <== credRoot1"],
  ];
  for (const [label, mutate, needle] of cases) {
    test(label, async () => assertRejectedBy(mutate(), needle));
  }
});

describe("a session cannot outlive the credential behind it", () => {
  test("validUntil one second past regime 0's expiry", async () => {
    await assertRejectedBy({ ...base, validUntil: (B(base.cred0ExpiresAt) + 1n).toString() }, "exp0Ok === 1");
  });
  test("a shorter session is always allowed", async () => {
    await assertAccepted({ ...base, validUntil: (B(base.validUntil) - 1000n).toString() });
  });
  // The fixture gives regime 1 the no-expiry escape (`cred1ExpiresAt == 0`), so its comparator was
  // reached by nothing. Re-issuing with a real expiry is the only way in.
  test("regime 1's comparator rejects an expired credential", async () => {
    await assertRejectedBy(await withRegime1Expiry(B(base.validUntil) - 1n), "exp1Ok === 1");
  });
  test("regime 1 at exactly validUntil is satisfiable: the boundary is inclusive", async () => {
    await assertAccepted(await withRegime1Expiry(B(base.validUntil)));
  });
});

describe("the pseudonym is bound to one contract and one commitment", () => {
  const PC = "pseudonymCommitment === pc.out", IRC = "ikRefCommitment === irc.out";
  const cases = [
    ["a commitment opened with a different blinding factor", () => bump("blindingR"), PC],
    // PER-CONTRACT PSEUDONYMS, in-circuit: the fold ends in `gatedContract`, so a session proven
    // for one venue cannot be re-aimed at another while keeping its commitment.
    ["a session re-aimed at a different gated contract", () => bump("gatedContract"), PC],
    ["a tampered pseudonym commitment", () => bump("pseudonymCommitment"), PC],
    ["a keeper reference the credential does not support", () => bump("ikRefCommitment"), IRC],
    ["a re-blinded keeper reference", () => bump("ikBlind"), IRC],
  ];
  for (const [label, mutate, needle] of cases) {
    test(label, async () => assertRejectedBy(mutate(), needle));
  }
});

describe("a flagged holder cannot open a session", () => {
  // What makes a Transaction Monitor's flag bite. The rest of revocation is contract-side; this is
  // the half that must hold even when the holder writes their own witness.
  test("the holder's own pseudonym is in the risk database", async () => {
    const pn = await pseudonym();
    const t = new gc.IndexedTree(RDB_DEPTH);
    await t.init();
    await t.insert(pn > 1n ? pn - 1n : pn + 1n); // an unrelated flagged key
    await t.insert(pn); // the TM flags this holder
    // Their best available witness: the predecessor leaf, whose successor IS their pseudonym. No
    // bracket exists, so the strict `key < nextKey` cannot hold.
    const w = t.lowLeafFor(pn);
    await assertRejectedBy({ ...base, riskRoot: t.root().toString(),
      rdbLowKey: w.lowKey.toString(), rdbNextKey: w.nextKey.toString(),
      rdbSiblings: w.siblings.map(String), rdbPathIndices: w.pathIndices.map(String) },
    "nonIncl.root <== riskRoot");
  });
  const cases = [
    ["a fabricated low leaf", () => bump("rdbLowKey")],
    ["a widened bracket", () => bump("rdbNextKey")],
    ["a forged risk-tree path", () => bumpAt("rdbSiblings", 0)],
    ["a stale risk root", () => bump("riskRoot")],
  ];
  for (const [label, mutate] of cases) {
    test(label, async () => assertRejectedBy(mutate(), "nonIncl.root <== riskRoot"));
  }
});

describe("the predicate is the one the registry published", () => {
  const cases = [
    ["a relaxed clause threshold", () => bumpAt("clValue", 0)],
    ["an extra clause switched on",
      () => ({ ...base,
        clEnabled: base.clEnabled.map((v, i) => (i === 2 ? "1" : v)),
        clOp: base.clOp.map((v, i) => (i === 2 ? "1" : v)),      // EQ: a WELL-FORMED clause, so the
        clValue: base.clValue.map((v, i) => (i === 2 ? "840" : v)) })], // fold is what rejects it
    ["a substituted clauses hash", () => bump("clausesHash")],
  ];
  for (const [label, mutate] of cases) {
    test(label, async () => assertRejectedBy(mutate(), "clausesHash === fold.out"));
  }

  // The predicate itself, reached only by re-issuing the credential: a holder whose attested
  // attributes genuinely fail the policy cannot prove the policy.
  test("a sanctioned holder with a genuinely re-issued credential", async () => {
    const attrs = base.attrs.map(B);
    attrs[1] = 1n; // sanctions hit: the clause set requires attrs[1] == 0
    await assertRejectedBy(await withRegime0(attrs), "dnfOk === 1");
  });

  // Found by this file's own blame assertion: switching on a spare slot is rejected before the fold
  // is reached, because the slot carries `op == NONE`. A separate rule, covered by nothing else: a
  // test accepting any error would have called the fold tested and been wrong about which held.
  test("a clause switched on while still carrying op == NONE", async () => {
    await assertRejectedBy(
      { ...base, clEnabled: base.clEnabled.map((v, i) => (i === 2 ? "1" : v)) },
      "enabled * opIsNone.out === 0",
      { file: POLICY, template: "ClauseEval" },
    );
  });

  test("an attribute too large for the 64-bit comparators", async () => {
    const attrs = base.attrs.map(B);
    attrs[0] = 2n ** 64n;
    await assertRejectedBy(await withRegime0(attrs), "attrBits[i].in <== attrs[i]");
  });
});

describe("the five public inputs the circuit does NOT constrain", () => {
  // These reach the circuit only through `bindSink`, multiplied by zero, so mutating any of them
  // still yields a witness. By design, but it means the ENTIRE security of these five slots is the
  // matching `require` in SessionManager, and every one of those five was asserted by no test until
  // `SessionManager.t.sol` grew its binding cases. Pinned here so the division of labour is a
  // tested fact: add a real in-circuit constraint on one of these and this test says so.
  const sinks = [
    ["chainId", "pub[1], SM: chainId binding"],
    ["sessionManager", "pub[2], SM: SM binding"],
    ["accountNonce", "pub[5], SM: nonce binding"],
    ["ordbId", "pub[13], SM: ORDB binding"],
    ["monitorKeyId", "pub[18], SM: monitor key binding"],
  ];
  for (const [slot, enforcedBy] of sinks) {
    test(`${slot} carries no in-circuit meaning; it is held by ${enforcedBy}`, async () => {
      await assertAccepted(bump(slot));
    });
  }
});
