import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import test from "node:test";
import {
  CRED_TAG,
  P,
  WF_CIRCUITS,
  WF_CIRCUIT_IDS,
  assertWfPublicSignals,
  decodeWfPublicSignals,
  wfCircuitInput,
  type WfCircuitId,
} from "../src/index";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (path: string) => readFileSync(resolve(repoRoot, path), "utf8");

test("each well-formedness circuit pins its own public-signal layout", () => {
  assert.deepEqual([...WF_CIRCUIT_IDS], [
    "saltBinding",
    "credentialWellFormed",
    "pseudonymWellFormed",
  ]);
  assert.deepEqual(WF_CIRCUITS.saltBinding.publicSignals, ["saltCommitment"]);
  assert.deepEqual(WF_CIRCUITS.credentialWellFormed.publicSignals, [
    "leaf",
    "saltCommitment",
    "ita",
    "regimeHash",
    "did",
    "attrsHash",
    "ikId",
    "expiresAt",
  ]);
  assert.deepEqual(WF_CIRCUITS.pseudonymWellFormed.publicSignals, [
    "saltCommitment",
    "did",
    "regimeHash",
    "gatedContract",
    "masterPseudonym",
    "pseudonym",
  ]);
  // The salt is a private witness of all three, and appears in no layout.
  for (const id of WF_CIRCUIT_IDS) {
    assert.ok(WF_CIRCUITS[id].privateInputs.includes("salt"));
    assert.ok(!WF_CIRCUITS[id].publicSignals.includes("salt" as never));
  }
});

test("public-signal validation is per circuit, not a shared 19-slot assumption", () => {
  assert.equal(assertWfPublicSignals("saltBinding", ["7"]).length, 1);
  assert.throws(
    () => assertWfPublicSignals("saltBinding", ["7", "8"]),
    /saltBinding: expected 1 public signals, got 2/,
  );
  assert.throws(
    () => assertWfPublicSignals("credentialWellFormed", Array(19).fill("0")),
    /expected 8 public signals, got 19/,
  );
  assert.throws(
    () => assertWfPublicSignals("pseudonymWellFormed", [...Array(5).fill("0"), P.toString()]),
    /public signal 5 \(pseudonym\) is outside the BN254 field/,
  );
});

test("decoding names every slot, so an IK never compares by index", () => {
  const decoded = decodeWfPublicSignals("pseudonymWellFormed", ["1", "2", "3", "4", "5", "6"]);
  assert.deepEqual(decoded, {
    saltCommitment: 1n,
    did: 2n,
    regimeHash: 3n,
    gatedContract: 4n,
    masterPseudonym: 5n,
    pseudonym: 6n,
  });
});

test("circuit input carries the private salt and every declared public, as decimal strings", () => {
  const input = wfCircuitInput("pseudonymWellFormed", {
    salt: 12n,
    saltCommitment: 1n,
    did: 2n,
    regimeHash: 3n,
    gatedContract: 4n,
    masterPseudonym: 5n,
    pseudonym: 6n,
  });
  assert.deepEqual(input, {
    salt: "12",
    saltCommitment: "1",
    did: "2",
    regimeHash: "3",
    gatedContract: "4",
    masterPseudonym: "5",
    pseudonym: "6",
  });

  const cred = wfCircuitInput("credentialWellFormed", {
    salt: 12n,
    attrs: [840n, 0n, 840n, 0n],
    leaf: 1n,
    saltCommitment: 2n,
    ita: 3n,
    regimeHash: 4n,
    did: 5n,
    attrsHash: 6n,
    ikId: 7n,
    expiresAt: 8n,
  });
  assert.deepEqual(cred.attrs, ["840", "0", "840", "0"]);
  assert.equal(cred.salt, "12");
  assert.equal(cred.leaf, "1");
});

test("a field element at or above the modulus is refused before it reaches a witness", () => {
  assert.throws(
    () => wfCircuitInput("saltBinding", { salt: P, saltCommitment: 1n }),
    /salt is outside the BN254 field/,
  );
});

test("the credential tag is one constant, mirrored into the well-formedness gadgets", () => {
  const gadgets = read("circuits/src/v2/lib/wf_gadgets.circom");
  const session = read("circuits/src/v2/lib/gap_session.circom");
  const tag = String(CRED_TAG);
  assert.ok(session.includes(tag), "gap_session.circom must carry the canonical tag");
  assert.ok(gadgets.includes(tag), "wf_gadgets.circom must carry the SAME tag literal");
});

test("the well-formedness gadgets fold through H2Chain rather than re-implementing Poseidon", () => {
  const gadgets = read("circuits/src/v2/lib/wf_gadgets.circom");
  assert.ok(gadgets.includes('include "./policy.circom";'), "H2Chain must come from the session lib");
  assert.ok(
    !/component\s+\w+\s*=\s*Poseidon\(/.test(gadgets),
    "a raw Poseidon component here is a second transcription of the session's folds",
  );
});

test("the build script's pinned counts are the same numbers the SDK pins", () => {
  const script = read("scripts/v2/build-wf.sh");
  const pinned = new Map<string, number>();
  for (const line of script.split("\n")) {
    const match = /^\s*"(wf_[a-z_]+):([^:]+):(\d+):(\d+)"\s*$/.exec(line);
    if (match) pinned.set(match[1], Number(match[4]));
  }
  assert.equal(pinned.size, 3, "build-wf.sh must declare exactly the three circuits");
  for (const id of WF_CIRCUIT_IDS) {
    const layout = WF_CIRCUITS[id];
    assert.equal(
      pinned.get(layout.circuit),
      layout.publicSignals.length,
      `${layout.circuit} public-signal count must be pinned identically in build-wf.sh`,
    );
  }
});

test("every main wrapper declares exactly its layout's publics, in order", () => {
  for (const id of WF_CIRCUIT_IDS as readonly WfCircuitId[]) {
    const layout = WF_CIRCUITS[id];
    const source = read(layout.main);
    const declared = /\{public\s*\[([^\]]*)\]\}/.exec(source);
    assert.ok(declared, `${layout.main} must declare a public list`);
    const names = declared[1]
      .split(",")
      .map((name) => name.trim())
      .filter((name) => name.length > 0);
    assert.deepEqual(names, [...layout.publicSignals], `${layout.main} public order`);
  }
});
