// A VERIFIER IS THE ONE ARTIFACT WHOSE CORRECTNESS LIVES ON A CHAIN.
//
// Everything else here is checked artifact-against-artifact, and that was enough to report MATCH
// while a testnet deployment held a verifier for a circuit two commits stale. A change that blinded
// the spending leaf regenerated the circuit, the zkey, the verification key and the
// verifier: all together, all self-consistent, and the deployment was never redone. The
// source-digest check could not see it, because the file it hashes was regenerated too.
//
// These tests bind the two directions a digest alone cannot: same source can mean different
// bytecode, and different source can still leave the source digest agreeing with itself.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  bindingVerdict, codeBytes, digestOfCode, keyPresence, verificationKeyWords,
} from "./deployed-bytecode.mjs";
import { LANES, checkVerifierBinding, locallyBuiltRuntimeCode } from "./verifier-binding.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => readFileSync(path.join(ROOT, relative), "utf8");

// LANES holds the lanes with a PERSISTENT deployment to check against. The v2 lane redeploys to a
// fresh chain on every `make up`, so it has no address to read, but its manifest↔build binding
// is the same claim and drifts the same way, so it is covered here too.
const BUILD_BOUND = Object.freeze([
  ...Object.values(LANES).map(({ contract, artifacts, verificationKey }) =>
    ({ contract, artifacts, verificationKey })),
  {
    contract: "SessionVerifier",
    artifacts: "circuits/keys/v2/local-artifact-manifest.json",
    verificationKey: "circuits/keys/v2/verification_key.json",
  },
]);

test("every lane's artifact manifest records the bytecode its verifier deploys as", () => {
  for (const [name, lane] of Object.entries(LANES)) {
    const manifest = JSON.parse(read(lane.artifacts));
    assert.match(
      manifest.deployedBytecodeSha256 ?? "", /^[0-9a-f]{64}$/,
      `${lane.artifacts} records no deployedBytecodeSha256. Without it the only binding to a ` +
        `chain is a source digest, which reported MATCH while the ${name} lane ran a verifier ` +
        `for a different circuit.`,
    );
  }
});

test("the recorded bytecode is what the committed source compiles to", () => {
  for (const lane of BUILD_BOUND) {
    const manifest = JSON.parse(read(lane.artifacts));
    assert.equal(
      digestOfCode(locallyBuiltRuntimeCode(lane.contract)), manifest.deployedBytecodeSha256,
      `${lane.contract} compiles to bytecode the manifest does not record. The manifest is ` +
        `describing a build that is not this one.`,
    );
  }
});

test("a verifier holds the verification key committed beside it", () => {
  for (const lane of BUILD_BOUND) {
    const key = JSON.parse(read(lane.verificationKey));
    const { found, total } = keyPresence(locallyBuiltRuntimeCode(lane.contract), key);
    assert.equal(
      found, total,
      `only ${found}/${total} of ${lane.verificationKey}'s field elements appear in ` +
        `${lane.contract}'s bytecode: the verifier and the key beside it came from different ` +
        `builds, and proofs made with that key cannot satisfy that verifier.`,
    );
  }
});

test("a field element with a zero top byte is still found", () => {
  // solc pushes a constant with the narrowest opcode that holds it, so an element whose leading
  // byte is zero occupies 31 bytes, not 32. Searching for zero-padded words silently missed
  // exactly one element of the base-fund key and made a correct build score 53/54, which meant
  // the "all present" branch was unreachable and every mismatch read as a circuit change.
  const short = (2n ** 248n) - 9n;                     // 248 bits = 31 bytes, so the
                                                      // 32-byte word would lead with 0x00
  const key = { vk_alpha_1: [short.toString(), "1"], IC: [] };
  const words = verificationKeyWords(key);
  assert.equal(words.length, 1, "a 1-byte element is too short to search for and must be dropped");
  assert.equal(words[0].length, 31, "the element must be searched for as solc encodes it");
  const code = Buffer.concat([Buffer.from("6000", "hex"), words[0], Buffer.from("50", "hex")]);
  assert.deepEqual(keyPresence(code, key), { found: 1, total: 1 });
});

test("an address holding no code is a refusal, not an absence of evidence", () => {
  const verdict = bindingVerdict({ deployed: codeBytes("0x"), expectedSha256: "a".repeat(64) });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, "no-contract");
});

test("a mismatch says which KIND of mismatch it is", () => {
  const key = JSON.parse(read(Object.values(LANES)[0].verificationKey));
  const built = locallyBuiltRuntimeCode(Object.values(LANES)[0].contract);

  // Same key, different bytes: a recompile. The operator needs to know the circuit did not move.
  const recompiled = Buffer.concat([built, Buffer.from("00", "hex")]);
  const settings = bindingVerdict({
    deployed: recompiled, expectedSha256: digestOfCode(built), verificationKey: key,
  });
  assert.equal(settings.ok, false);
  assert.match(settings.detail, /compiler settings or metadata, not the circuit/);

  // A verifier that embeds none of this key is a different circuit entirely.
  const foreign = Buffer.alloc(3000, 0x5b);
  const other = bindingVerdict({
    deployed: foreign, expectedSha256: digestOfCode(built), verificationKey: key,
  });
  assert.match(other.detail, /verifier for a DIFFERENT circuit/);
});

test("an unreachable chain is never a pass", async () => {
  await assert.rejects(
    checkVerifierBinding("base-fund", {
      fetchCodeFor: async () => { throw new Error("network down"); },
    }),
    /network down/,
    "a binding that could not be read must fail, not default to ok",
  );
});

test("the check reports a mismatch rather than throwing, so callers can act on it", async () => {
  const result = await checkVerifierBinding("base-fund", {
    fetchCodeFor: async () => Buffer.alloc(3000, 0x5b),
  });
  assert.equal(result.verdict.ok, false);
  assert.equal(result.built, result.expectedSha256, "the local build must agree with the manifest");
});
