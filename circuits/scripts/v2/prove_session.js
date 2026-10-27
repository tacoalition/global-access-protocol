#!/usr/bin/env node
/**
 * GAP v2 session-proof builder.
 *
 * Two modes:
 *   node prove_session.js selftest [outDir]
 *       Builds a fully self-consistent scenario (computes all roots offchain),
 *       generates a Groth16 proof, writes proof.json / public.json / scenario.json.
 *       Used by contracts/test to drive a real proof through the on-chain verifier.
 *
 *   node prove_session.js prove <inputJson> <outDir>
 *       Proves against a caller-supplied scenario (used by the CLI). The inputJson
 *       carries the private witnesses + the public roots read from chain.
 *
 * Depths MUST match circuits/src/v2/session.circom: DID 16, SK 4, CRED 16, RDB 14.
 */
const fs = require("fs");
const path = require("path");
const { groth16 } = require("snarkjs");
const gc = require("./gap_crypto");

const DID_DEPTH = 16, SK_DEPTH = 4, CRED_DEPTH = 16, RDB_DEPTH = 14;
const ROOT = path.resolve(__dirname, "../../..");
const WASM = path.join(ROOT, "circuits/build/v2/session_js/session.wasm");
const ZKEY = path.join(ROOT, "circuits/keys/v2/session_final.zkey");

// keccak256("GAP_ATTR_CRED_V3") mod P (must equal GapLib.credTag and the circuit CRED_TAG)
const CRED_TAG = 7398619034839472060957547841361825911550539606183619483712186628328937676175n;
// keccak256("GAP_SPENDING_BLIND_V2") mod P, blinds the spending leaf (SPENDING_SET_PRIVACY.md)
const SPENDING_BLIND_TAG = 20739668207314188630064942382150002554459284316356860011996029219836196127177n;

async function buildScenario() {
  // Deterministic demo identity + two anchors.
  const did = 111111111111111111n;
  const privateSalt = 222222222222222222n;
  const account = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8n; // anvil acct #1
  const ita0 = 0x1111111111111111111111111111111111111111n;
  const ita1 = 0x2222222222222222222222222222222222222222n;
  const regime0 = gc.keccakToField(0xaaaabbbbn); // "standard-identity" regime hash (demo)
  const regime1 = gc.keccakToField(0xccccddddn); // "investor-status" regime hash (demo)
  const ikId0 = gc.keccakToField(0x1234n);
  const ikId1 = gc.keccakToField(0x5678n);
  const gatedContract = 0x5FbDB2315678afecb367f032d93F642f64180aa3n; // token addr (demo)
  const ordbId = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512n;
  const sessionManager = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0n;
  const chainId = 31337n;
  const accountNonce = 0n;
  const validUntil = 4000000000n;
  const monitorKeyId = gc.keccakToField(0xdeadbeefn);
  const blindingR = 999999999n;

  // attributes: regime0 => [citizenship=840(USA), sanctioned=0]; regime1 => [accredited=1, qp=1]
  // GAP_ATTR_CRED_V3: regime 0 = [residency, sanctions, citizenship, reserved],
  // regime 1 = [accredited, qualifiedPurchaser, reserved, reserved].
  const attrs = [840n, 0n, 840n, 0n, 1n, 1n, 0n, 0n];

  // --- DID tree: leaf = H2(H2(did, saltCommit), spendingKeyRoot) ---
  const saltCommit = await gc.h2(privateSalt, 0n);
  // spending-key tree: leaf H2(account, H2(privateSalt, SPENDING_BLIND_TAG)). The blind is what
  // stops the published root being a preimage of the holder's wallets: the circuit derives the
  // same value from the same private salt. SPENDING_SET_PRIVACY.md (full stack, not in this repository).
  const spendingBlind = await gc.h2(privateSalt, SPENDING_BLIND_TAG);
  const skTree = new gc.SparseTree(SK_DEPTH); await skTree.init();
  const skLeaf = await gc.h2(account, spendingBlind);
  skTree.setByKey(account, skLeaf);
  const spendingKeyRoot = skTree.root();
  const skProof = skTree.proof(skTree.indexOf(account));

  const didInner = await gc.h2(did, saltCommit);
  const didLeaf = await gc.h2(didInner, spendingKeyRoot);
  const didTree = new gc.SparseTree(DID_DEPTH); await didTree.init();
  didTree.setByKey(did, didLeaf);
  const didRoot = didTree.root();
  const didProof = didTree.proof(didTree.indexOf(did));

  // --- credential trees (one per regime) ---
  // cred0 expires AFTER validUntil (exercises the live comparator); cred1 never expires
  // (exercises the 0-escape): both GAP-H2 paths are proven in the fixture.
  const cred0ExpiresAt = 5000000000n; // > validUntil (4000000000)
  const cred1ExpiresAt = 0n;
  // attrsHash is a genuine Poseidon(4) over the regime's four attributes, NOT gc.chain of
  // four items, which is a different function. Mirrors AttrsHash() in policy.circom.
  async function credLeaf(ita, regime, ikId, regimeAttrs, expiresAt) {
    const attrsHash = await gc.h4(regimeAttrs[0], regimeAttrs[1], regimeAttrs[2], regimeAttrs[3]);
    return gc.chain([CRED_TAG, ita, regime, did, attrsHash, privateSalt, ikId, expiresAt]);
  }
  const leaf0 = await credLeaf(ita0, regime0, ikId0, attrs.slice(0, 4), cred0ExpiresAt);
  const leaf1 = await credLeaf(ita1, regime1, ikId1, attrs.slice(4, 8), cred1ExpiresAt);
  const cred0Tree = new gc.SparseTree(CRED_DEPTH); await cred0Tree.init(); cred0Tree.setByKey(did, leaf0);
  const cred1Tree = new gc.SparseTree(CRED_DEPTH); await cred1Tree.init(); cred1Tree.setByKey(did, leaf1);
  const credRoot0 = cred0Tree.root(), credRoot1 = cred1Tree.root();
  const cred0Proof = cred0Tree.proof(cred0Tree.indexOf(did));
  const cred1Proof = cred1Tree.proof(cred1Tree.indexOf(did));

  // --- pseudonym + ORDB full-key NON-membership (GAP-H1) ---
  // Indexed tree with one unrelated flagged key, so the fixture exercises a real low leaf
  // (not just the genesis) bracketing the pseudonym.
  const pn1 = await gc.h2(did, privateSalt);
  const pn2 = await gc.h2(pn1, regime0);
  const pseudonym = await gc.h2(pn2, gatedContract);
  const rdbTree = new gc.IndexedTree(RDB_DEPTH); await rdbTree.init();
  await rdbTree.insert(pseudonym > 1n ? pseudonym - 1n : pseudonym + 1n); // neighbor ≠ pseudonym
  const riskRoot = rdbTree.root();
  const rdbWitness = rdbTree.lowLeafFor(pseudonym);

  // --- commitments ---
  const pseudonymCommitment = await gc.h2(pseudonym, blindingR);
  // BLINDED. Both of this commitment's other preimages are public, `ita0` is an address and
  // `ikId0` is emitted by `IKRegistered`, so a 2-ary hash of them inverted by table lookup and
  // named the Identity Keeper to anyone reading the chain.
  // FIXED, like blindingR above: this generates the committed fixture, and `make repro` requires it
  // to be byte-for-byte reproducible. A random value here would make the verifier unreproducible.
  const ikBlind = 123456789n;
  const ikRefCommitment = await gc.h3(ita0, ikId0, ikBlind);

  // --- DNF policy: (residency==840 AND sanctioned==0) [group 0], MAX_CLAUSES = 6 ---
  const clauses = [
    { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n }, // EQ residency
    { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },   // EQ not sanctioned
    { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  ];
  // clausesHash = fold(0, meta0, value0, meta1, value1, ...)
  const foldItems = [0n];
  for (const c of clauses) {
    const meta = BigInt(c.enabled) | (BigInt(c.groupId) << 8n) | (BigInt(c.attrIndex) << 16n) | (BigInt(c.op) << 24n);
    foldItems.push(meta, c.value);
  }
  const clausesHash = await gc.chain(foldItems);

  const input = {
    // public
    account: account.toString(), chainId: chainId.toString(),
    sessionManager: sessionManager.toString(), clausesHash: clausesHash.toString(),
    validUntil: validUntil.toString(), accountNonce: accountNonce.toString(),
    didRoot: didRoot.toString(),
    ita0: ita0.toString(), regimeHash0: regime0.toString(), credRoot0: credRoot0.toString(),
    ita1: ita1.toString(), regimeHash1: regime1.toString(), credRoot1: credRoot1.toString(),
    ordbId: ordbId.toString(), riskRoot: riskRoot.toString(), gatedContract: gatedContract.toString(),
    pseudonymCommitment: pseudonymCommitment.toString(), ikRefCommitment: ikRefCommitment.toString(),
    monitorKeyId: monitorKeyId.toString(),
    // private
    did: did.toString(), privateSalt: privateSalt.toString(), ikBlind: ikBlind.toString(), spendingKeyRoot: spendingKeyRoot.toString(),
    didSiblings: didProof.siblings.map(String), didPathIndices: didProof.pathIndices.map(String),
    skSiblings: skProof.siblings.map(String), skPathIndices: skProof.pathIndices.map(String),
    attrs: attrs.map(String),
    ikId0: ikId0.toString(), ikId1: ikId1.toString(),
    cred0ExpiresAt: cred0ExpiresAt.toString(), cred1ExpiresAt: cred1ExpiresAt.toString(),
    cred0Siblings: cred0Proof.siblings.map(String), cred0PathIndices: cred0Proof.pathIndices.map(String),
    cred1Siblings: cred1Proof.siblings.map(String), cred1PathIndices: cred1Proof.pathIndices.map(String),
    rdbLowKey: rdbWitness.lowKey.toString(), rdbNextKey: rdbWitness.nextKey.toString(),
    rdbSiblings: rdbWitness.siblings.map(String), rdbPathIndices: rdbWitness.pathIndices.map(String),
    blindingR: blindingR.toString(),
    clEnabled: clauses.map((c) => String(c.enabled)),
    clGroupId: clauses.map((c) => String(c.groupId)),
    clAttrIndex: clauses.map((c) => String(c.attrIndex)),
    clOp: clauses.map((c) => String(c.op)),
    clValue: clauses.map((c) => c.value.toString()),
  };
  return { input, pseudonym, blindingR, clauses };
}

// Public-signal order MUST match SessionManager's 19-slot layout.
const PUBLIC_ORDER = [
  "account", "chainId", "sessionManager", "clausesHash", "validUntil", "accountNonce",
  "didRoot", "ita0", "regimeHash0", "credRoot0", "ita1", "regimeHash1", "credRoot1",
  "ordbId", "riskRoot", "gatedContract", "pseudonymCommitment", "ikRefCommitment", "monitorKeyId",
];

async function proveInput(input, outDir) {
  const { proof, publicSignals } = await groth16.fullProve(input, WASM, ZKEY);
  fs.mkdirSync(outDir, { recursive: true });
  // Solidity calldata form.
  const pA = [proof.pi_a[0], proof.pi_a[1]];
  const pB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
  const pC = [proof.pi_c[0], proof.pi_c[1]];
  fs.writeFileSync(path.join(outDir, "proof.json"), JSON.stringify({ pA, pB, pC }, null, 2));
  fs.writeFileSync(path.join(outDir, "public.json"), JSON.stringify(publicSignals, null, 2));
  return { proof, publicSignals, pA, pB, pC };
}

// GAP-H2 constraint checks: witness satisfaction == constraint satisfaction, so computing a
// witness for a mutated input proves/refutes satisfiability without a full Groth16 proof.
async function expiryConstraintChecks(input) {
  const wcBuilder = require(path.join(ROOT, "circuits/build/v2/session_js/witness_calculator.js"));
  const calc = await wcBuilder(fs.readFileSync(WASM));
  // boundary: validUntil == cred0ExpiresAt must SATISFY (LessEqThan)
  await calc.calculateWitness({ ...input, validUntil: input.cred0ExpiresAt }, 1);
  // one past the boundary must be UNSATISFIABLE: the leaf pins expiresAt, so there is no way out
  let bit = false;
  try {
    await calc.calculateWitness(
      { ...input, validUntil: (BigInt(input.cred0ExpiresAt) + 1n).toString() }, 1);
  } catch { bit = true; }
  if (!bit) throw new Error("GAP-H2 check FAILED: validUntil > expiresAt produced a witness");
  console.log("GAP-H2 expiry constraint: boundary ok, past-boundary unsatisfiable ✓");
}

async function main() {
  const [mode, arg1, arg2] = process.argv.slice(2);
  if (mode === "selftest") {
    const outDir = arg1 || path.join(ROOT, "contracts/test/fixtures/v2");
    const { input, pseudonym } = await buildScenario();
    await expiryConstraintChecks(input);
    const { proof, publicSignals } = await proveInput(input, outDir);
    fs.writeFileSync(path.join(outDir, "scenario.json"),
      JSON.stringify({ input, pseudonym: pseudonym.toString(), publicOrder: PUBLIC_ORDER }, null, 2));
    // sanity: verify offchain
    const vkey = JSON.parse(fs.readFileSync(path.join(ROOT, "circuits/keys/v2/verification_key.json")));
    const ok = await groth16.verify(vkey, publicSignals, proof);
    console.log("offchain verify:", ok);
    console.log("public[16] pseudonymCommitment:", publicSignals[16]);
    console.log("wrote fixtures to", outDir);
    process.exit(ok ? 0 : 1);
  } else if (mode === "prove") {
    const input = JSON.parse(fs.readFileSync(arg1));
    await proveInput(input, arg2);
    console.log("proof written to", arg2);
  } else {
    console.error("usage: prove_session.js selftest|prove ...");
    process.exit(2);
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
