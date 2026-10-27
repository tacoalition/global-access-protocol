// WHAT THIS BINDS. A Groth16 verifier is only as trustworthy as the phase-2 close behind it, and
// the repository makes two DIFFERENT promises about that close:
//
//   development builds: "you can regenerate this exact verifier from the committed circuit"
//   the wf ceremony: "nobody, including us, can regenerate the trapdoor behind this verifier"
//
// Those promises need opposite mechanics. Reproducibility needs a fixed, published closing value.
// Soundness needs entropy that never touches disk. `snarkjs zkey contribute` gives neither cleanly:
// measured on this repository, it reseeds from OS entropy even when handed a fixed seed on stdin,
// so two runs of the same script over the same circuit produce two different zkeys. Using it in a
// development build bought no soundness (the seed was a string literal in the script) and cost all
// the reproducibility. Development builds therefore close with `zkey beacon` on a published
// constant; the ceremony keeps `zkey contribute`, interactively, and closes on public randomness.
//
// The failure this guards is the swap going the WRONG way: someone tidying the ceremony to match
// the "deterministic" development scripts, silently turning a real ceremony into a reproducible
// one whose trapdoor is a repository constant. That change would look like cleanup and would pass
// every other test in this suite.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { rewriteVerifier, DEVELOPMENT_MARKER } from "./verifier-rewrite.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => readFileSync(path.join(ROOT, relative), "utf8");

const CEREMONY = "scripts/v2/wf-ceremony.sh";
const DEV_BEACON = "scripts/v2/lib/dev-beacon.sh";

// Every script that closes a phase 2 and hands the result to a committed artifact.
// The Base Fund lane's build was a third entry upstream. That lane is a product-specific
// integration and is not in this repository; the rule it was held to is unchanged for the builds
// that remain. Add any new build here: a build absent from this list is one nothing checks.
const DEVELOPMENT_BUILDS = Object.freeze([
  "scripts/v2/build.sh",
  "scripts/v2/build-wf.sh",
]);

test("no development build closes phase 2 with a non-reproducible contribution", () => {
  for (const script of DEVELOPMENT_BUILDS) {
    const source = read(script);
    const closes = source
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .filter((line) => /zkey\s+contribute/.test(line));
    assert.deepEqual(
      closes, [],
      `${script} closes phase 2 with 'zkey contribute', which is not reproducible: the ` +
        `verifier it produces cannot be regenerated from the committed circuit by CI, by a ` +
        `second engineer, or by an auditor. Close with 'zkey beacon' on ${DEV_BEACON}.`,
    );
  }
});

test("every development build closes on the shared published beacon, not its own literal", () => {
  for (const script of DEVELOPMENT_BUILDS) {
    const source = read(script);
    assert.match(
      source, /^\s*\.\s+.*dev-beacon\.sh"?\s*$/m,
      `${script} does not source ${DEV_BEACON}; a build carrying its own inline closing value is ` +
        `a second place the constant has to be kept in step.`,
    );
    const beaconCall = source.slice(source.search(/zkey\s+beacon/));
    assert.match(
      beaconCall, /\$DEV_BEACON_HEX/,
      `${script} calls 'zkey beacon' with something other than $DEV_BEACON_HEX.`,
    );
    assert.match(
      beaconCall, /\$DEV_BEACON_ITERATIONS/,
      `${script} calls 'zkey beacon' without $DEV_BEACON_ITERATIONS; the iteration count is part ` +
        `of the closing value and a different count is a different zkey.`,
    );
  }
});

test("the ceremony never degrades to the reproducible development close", () => {
  const source = read(CEREMONY);
  assert.match(
    source, /snarkjs zkey contribute/,
    `${CEREMONY} no longer runs 'zkey contribute'. A ceremony whose close is reproducible has ` +
      `no trapdoor secret: every participant's contribution can be replayed from the repository.`,
  );
  assert.doesNotMatch(
    source, new RegExp(DEV_BEACON.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    `${CEREMONY} sources ${DEV_BEACON}. The development closing value is PUBLISHED; closing a ` +
      `ceremony on it hands the trapdoor to every reader of this repository.`,
  );
  assert.doesNotMatch(
    source, /\$DEV_BEACON_HEX/,
    `${CEREMONY} references $DEV_BEACON_HEX.`,
  );
});

test("the published development value declares that it is worthless", () => {
  const source = read(DEV_BEACON);
  assert.match(
    source, /^DEV_BEACON_HEX="[0-9a-f]{64}"$/m,
    `${DEV_BEACON} must publish a 64-hex closing value; snarkjs takes the beacon as hex.`,
  );
  const declared = source.match(/^DEV_BEACON_HEX="([0-9a-f]{64})"$/m)?.[1];
  const preimage = source.match(/^#\s+sha256\("(.+)"\)/m)?.[1];
  assert.ok(preimage, `${DEV_BEACON} must document the preimage of its closing value.`);
  assert.equal(
    declared, createHash("sha256").update(preimage, "utf8").digest("hex"),
    `${DEV_BEACON} declares a closing value that is NOT sha256 of the preimage it documents. A ` +
      `hand-chosen beacon is indistinguishable from one selected for its effect on the key.`,
  );
  assert.match(
    source, /NEVER use this in the ceremony path/,
    `${DEV_BEACON} must say, in the file, that it is not for the ceremony. The next reader ` +
      `decides from this file whether the constant is safe to reuse.`,
  );
});

test("a development verifier confesses in its own bytecode", () => {
  const marked = rewriteVerifier(
    "pragma solidity >=0.7.0 <0.9.0;\ncontract Groth16Verifier {\n}\n",
    { contractName: "SessionVerifier" },
  );
  assert.match(marked, new RegExp(`bool public constant ${DEVELOPMENT_MARKER} = true;`));
  assert.match(
    marked, /NOT sound/,
    "the marker needs prose beside it; a bare boolean does not tell a reader what is unsound.",
  );

  const production = rewriteVerifier(
    "pragma solidity >=0.7.0 <0.9.0;\ncontract Groth16Verifier {\n}\n",
    { contractName: "SessionVerifier", development: false },
  );
  assert.doesNotMatch(
    production, new RegExp(DEVELOPMENT_MARKER),
    "a ceremony-backed verifier must NOT claim to be a development artifact.",
  );
});

// Both verifiers a developer can build today. Neither is a ceremony product; both must say so on
// chain. The v2 one did not until this work: it was the more load-bearing of the two.
// One verifier here, not two: the Base Fund lane's is a product integration and is not in this
// repository. The requirement is the same: a verifier built from a development setup must SAY so
// on chain, because nothing else distinguishes it from a ceremony product once deployed.
const COMMITTED_DEVELOPMENT_VERIFIERS = Object.freeze([
  "contracts/src/v2/SessionVerifier.sol",
]);

test("every committed development verifier carries the marker", () => {
  for (const verifier of COMMITTED_DEVELOPMENT_VERIFIERS) {
    assert.match(
      read(verifier), new RegExp(`bool public constant ${DEVELOPMENT_MARKER} = true;`),
      `${verifier} does not declare itself a development artifact. Anyone reading the deployed ` +
        `contract has no way to tell it from a ceremony product. Rebuild it.`,
    );
  }
});

test("the pinned compiler is the one that built the committed artifacts", () => {
  // The reproducibility gate installs a pinned circom; the manifest records the circom that built
  // the committed bundle. If those two ever drift, CI fails on a compiler mismatch that has
  // nothing to do with the change under review, and the usual response to that is to switch the
  // gate off. Bind them here so the drift is caught at its source.
  const pin = read("scripts/v2/lib/fetch-circom.sh").match(/^CIRCOM_VERSION="([^"]+)"$/m)?.[1];
  assert.ok(pin, "scripts/v2/lib/fetch-circom.sh must pin CIRCOM_VERSION");
  const manifest = JSON.parse(read("circuits/keys/v2/local-artifact-manifest.json"));
  assert.equal(
    manifest.circomVersion, pin,
    `the manifest says circom ${manifest.circomVersion} built the committed artifacts, but ` +
      `scripts/v2/lib/fetch-circom.sh pins ${pin}. Rebuild with the pinned compiler, or move the ` +
      `pin, but not one without the other.`,
  );

  // Every pinned digest must be a real sha256, not a placeholder someone meant to fill in.
  const digests = [...read("scripts/v2/lib/fetch-circom.sh")
    .matchAll(/^CIRCOM_SHA256_\w+="([^"]*)"$/gm)].map(([, value]) => value);
  assert.ok(digests.length > 0, "fetch-circom.sh must pin at least one release digest");
  for (const digest of digests) {
    assert.match(digest, /^[0-9a-f]{64}$/, "a pinned circom digest is not a sha256");
    assert.notEqual(digest, "0".repeat(64), "a pinned circom digest is a placeholder");
  }
});

test("the committed form is defined once, not re-spelled per build", () => {
  // Everyone who needs the committed form: the two builds that produce one, and the checker that
  // has to compare against one, must come through the module. Detecting a re-spelling by pattern
  // is a losing game (a mutant that wrote the same regex escaped survived exactly that check), so
  // assert the positive: each file names the module.
  // The Base Fund lane's build (scripts/integrations/build-base-fund-local-circuit.sh) was a third
  // caller upstream. It is not in this repository: that lane is a product-specific integration,
  // not part of the reference implementation, so it is not listed. The assertion is unchanged in
  // kind: EVERY build that produces a committed form, and the checker that compares against one,
  // must come through the module. Add the caller here if a second build is ever added.
  const CALLERS = Object.freeze([
    "scripts/v2/build.sh",
    "scripts/v2/check-artifacts.mjs",
  ]);
  for (const file of CALLERS) {
    assert.match(
      read(file), /verifier-rewrite\.mjs/,
      `${file} does not go through scripts/v2/verifier-rewrite.mjs. Two spellings of one ` +
        `transform is how a checker ends up agreeing with a build that drifted.`,
    );
  }

  // And nobody but the module itself carries the snarkjs-export pragma, which is the tell that a
  // second copy of the rewrite has grown back.
  const respellers = [...CALLERS, "scripts/v2/build-wf.sh"]
    .filter((file) => /pragma solidity >=0\.7\.0/.test(read(file)));
  assert.deepEqual(
    respellers, [],
    `${respellers.join(", ")} carry the snarkjs-export pragma; the rewrite has been copied back ` +
      `out of scripts/v2/verifier-rewrite.mjs.`,
  );
});
