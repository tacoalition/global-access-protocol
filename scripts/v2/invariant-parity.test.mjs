// THE MIRRORS, ASSERTED. A handful of numbers in this repository have to agree across files that
// cannot see each other, and every one of them fails SILENTLY and LATE when it drifts: a proof that
// does not verify, or worse, a binding that is read from the wrong slot.
//
// Nothing checked them here. The full stack has a parity test; this repository did not, so a reader
// who changed the circuit's depth tuple and forgot the deploy script would learn about it from a
// revert during the demo, which is the worst place to find out.
//
// WHAT THIS DOES NOT DO: re-derive anything. It reads the literal numbers out of each file and
// asserts they match, which is exactly the check a human would do and reliably forget.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PUBLIC_SIGNAL_NAMES, LOCAL_CIRCUIT_METADATA } from "../../packages/gap-sdk/src/metadata.ts";

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), "utf8");

test("the public-signal layout matches the circuit IN ORDER, not merely in width", () => {
  // WIDTH WAS NEVER THE RISK. A review pointed out that this file checked only that everything was
  // 19 wide, while DEVELOPMENT.md warns that the SDK maps signals to bindings BY INDEX, so two
  // reordered slots still verify, against the wrong binding, and every check here still passed.
  //
  // The order that matters is the TEMPLATE'S DECLARATION ORDER, because that is what fixes a signal's
  // wire position. The `public [...]` list in session.circom selects which are public; it does not
  // order them. So this asserts against the declarations and then checks the two lists agree, which
  // means neither file can drift from the SDK without failing here.
  const lib = read("circuits/src/v2/lib/gap_session.circom");
  const declared = [...lib.matchAll(/^\s*signal input (\w+);/gm)].map((m) => m[1]);
  const publicInOrder = declared.filter((n) => PUBLIC_SIGNAL_NAMES.includes(n));
  assert.deepEqual(
    publicInOrder,
    [...PUBLIC_SIGNAL_NAMES],
    "the circuit's declaration order of the public signals IS the SDK's index map",
  );

  const main = read("circuits/src/v2/session.circom");
  const block = main.match(/component main \{public \[([^\]]+)\]\}/);
  assert.ok(block, "session.circom must declare its public signals");
  const listed = block[1].split(",").map((x) => x.trim()).filter(Boolean);
  assert.deepEqual(
    [...listed].sort(),
    [...PUBLIC_SIGNAL_NAMES].sort(),
    "the public[] list must name exactly the SDK's signals: no more, no fewer",
  );

  assert.equal(PUBLIC_SIGNAL_NAMES.length, 19, "the SDK's signal names ARE the layout");

  const sm = read("contracts/src/v2/SessionManager.sol");
  const widths = [...sm.matchAll(/uint256\[(\d+)\]\s+calldata\s+pub/g)].map((m) => Number(m[1]));
  assert.ok(widths.length > 0, "SessionManager must take a fixed-width public-input array");
  for (const w of widths) {
    assert.equal(w, 19, "SessionManager's pub[] width must match the SDK's signal names");
  }

  const verifier = read("contracts/src/v2/SessionVerifier.sol");
  const vWidths = [...verifier.matchAll(/uint256\[(\d+)\]\s+calldata\s+pubSignals/g)].map((m) => Number(m[1]));
  for (const w of vWidths) {
    assert.equal(w, 19, "the generated verifier's width must match too");
  }
});

test("the circuit's depth tuple matches the local profile and the deploy script", () => {
  // `GapSession(DID_DEPTH, SK_DEPTH, CRED_DEPTH, RDB_DEPTH, MAX_CLAUSES)`
  const circuit = read("circuits/src/v2/session.circom");
  const m = circuit.match(/GapSession\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/);
  assert.ok(m, "session.circom must instantiate GapSession with five literal parameters");
  const [, did, sk, cred, rdb, maxClauses] = m.map(Number);

  const local = LOCAL_CIRCUIT_METADATA;
  assert.equal(local.depths.did, did, "SDK did-depth vs circuit");
  assert.equal(local.depths.spendingKey, sk, "SDK spendingKey-depth vs circuit");
  assert.equal(local.depths.credential, cred, "SDK credential-depth vs circuit");
  assert.equal(local.depths.risk, rdb, "SDK risk-depth vs circuit");

  const deploy = read("contracts/script/v2/DeployV2.s.sol");
  const constant = (name) => {
    const mm = deploy.match(new RegExp(`${name}\\s*=\\s*(\\d+)`));
    assert.ok(mm, `DeployV2 must declare ${name}`);
    return Number(mm[1]);
  };
  assert.equal(constant("DID_DEPTH"), did, "DeployV2 DID_DEPTH vs circuit");
  assert.equal(constant("CRED_DEPTH"), cred, "DeployV2 CRED_DEPTH vs circuit");
  assert.equal(constant("ORDB_DEPTH"), rdb, "DeployV2 ORDB_DEPTH vs circuit");

  // The clause ceiling is a ptau-budget decision, not a preference: eight clauses measures 66,715
  // constraints at production depth and busts the 2^16 ceiling by 1,179.
  const registry = read("contracts/src/v2/UserPolicyRegistry.sol");
  const reg = registry.match(/MAX_CLAUSES\s*=\s*(\d+)/);
  assert.ok(reg, "UserPolicyRegistry must declare MAX_CLAUSES");
  assert.equal(Number(reg[1]), maxClauses, "UserPolicyRegistry MAX_CLAUSES vs circuit");
});

test("the attribute vocabulary is eight wide in the circuit and the registry", () => {
  const lib = read("circuits/src/v2/lib/gap_session.circom");
  assert.match(lib, /signal input attrs\[8\]/, "the circuit carries eight attributes");

  const registry = read("contracts/src/v2/UserPolicyRegistry.sol");
  assert.match(
    registry,
    /uint256\[8\]/,
    "UserPolicyRegistry must evaluate over the same eight attributes",
  );
});
