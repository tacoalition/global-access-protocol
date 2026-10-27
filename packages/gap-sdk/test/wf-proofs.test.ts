import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test, { after } from "node:test";
import {
  WF_CIRCUIT_IDS,
  createWfProver,
  decodeWfPublicSignals,
  credentialWellFormedWitness,
  pseudonymWellFormedWitness,
  saltBindingWitness,
  type ArtifactReference,
  type Hex,
  type WfArtifactSet,
  type WfCircuitId,
} from "../src/index";
import { realPoseidon } from "./wf-poseidon";

const require = createRequire(import.meta.url);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const pinsPath = resolve(repoRoot, "circuits/build/wf/pins.json");
const skip = existsSync(pinsPath)
  ? false
  : "development well-formedness artifacts absent, run scripts/v2/build-wf.sh";

/**
 * A SILENT SKIP IS INDISTINGUISHABLE FROM A PASS in a summary line, and this file is the only
 * place a real proof crosses the SDK↔circuit boundary. So one test ALWAYS runs, and its NAME
 * says which of the two worlds the suite is in, an operator reading the output cannot mistake
 * "nine circuit tests were skipped" for "nine circuit tests passed".
 */
test(
  skip
    ? "!! WELL-FORMEDNESS ARTIFACTS ARE ABSENT: every proof test below is SKIPPED"
      + ", run scripts/v2/build-wf.sh to actually cover them"
    : "the well-formedness artifacts are present, so the proof tests below really run",
  () => {
    assert.equal(existsSync(pinsPath), skip === false);
  },
);

interface PinnedCircuit {
  readonly wasm: string;
  readonly zkey: string;
  readonly verificationKey: string;
  readonly sha256: Record<string, Hex>;
}

/** Path artifacts, verified the way a Node consumer must: read the file, hash it, compare the pin. */
async function nodeVerifier(artifact: ArtifactReference): Promise<void> {
  if (typeof artifact.source !== "string") throw new Error("expected a path artifact");
  const actual = `0x${createHash("sha256").update(readFileSync(artifact.source)).digest("hex")}`;
  if (actual !== artifact.sha256.toLowerCase()) {
    throw new Error(`GAP SDK: artifact digest mismatch: expected ${artifact.sha256}, got ${actual}`);
  }
}

function artifactSet(circuit: PinnedCircuit): WfArtifactSet {
  const ref = (key: "wasm" | "zkey" | "verificationKey"): ArtifactReference => ({
    source: resolve(repoRoot, circuit[key]),
    sha256: circuit.sha256[key],
  });
  return { wasm: ref("wasm"), zkey: ref("zkey"), verificationKey: ref("verificationKey") };
}

const CIRCUIT_FILES: Record<WfCircuitId, string> = {
  saltBinding: "wf_salt_binding",
  credentialWellFormed: "wf_cred",
  pseudonymWellFormed: "wf_pseudonym",
};

function prover(overrides: Partial<Record<WfCircuitId, WfArtifactSet>> = {}) {
  const pins = JSON.parse(readFileSync(pinsPath, "utf8")) as {
    circuits: Record<string, PinnedCircuit>;
  };
  const artifacts = {} as Record<WfCircuitId, WfArtifactSet>;
  for (const id of WF_CIRCUIT_IDS) {
    artifacts[id] = overrides[id] ?? artifactSet(pins.circuits[CIRCUIT_FILES[id]]);
  }
  return createWfProver({
    // snarkjs has no stable exported TypeScript interface.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    groth16: (require("snarkjs") as any).groth16,
    artifacts,
    verifyArtifact: nodeVerifier,
    async readArtifact(artifact) {
      if (typeof artifact.source !== "string") throw new Error("expected a path artifact");
      return readFileSync(artifact.source);
    },
  });
}

/**
 * snarkjs caches a BN254 curve with a live worker pool on `globalThis`, and node:test waits for
 * the handle rather than exiting. `circuits/scripts/v2/prove_session.js` escapes the same hang
 * with `process.exit()`; a test file has to shut the pool down instead, or the suite never
 * reports and every consumer of it hangs behind a proof it already finished.
 */
after(async () => {
  const cached = globalThis as { curve_bn128?: { terminate(): Promise<void> } };
  await cached.curve_bn128?.terminate();
});

const identity = { did: 111111111111111111n, privateSalt: 222222222222222222n };
const ita = 0x1111111111111111111111111111111111111111n;
const regimeHash = 0xaaaabbbbn;
const ikId = 0x1234n;
const gatedContract = 0x5fbdb2315678afecb367f032d93f642f64180aa3n;
// regime 0 under GAP_ATTR_CRED_V3: residency, sanctions, citizenship, reserved.
const attrs: [bigint, bigint, bigint, bigint] = [840n, 0n, 840n, 0n];
const expiresAt = 4000000000n;

test("a device proves it holds the salt behind the registered commitment", { skip }, async () => {
  const crypto = await realPoseidon();
  const witness = await saltBindingWitness(crypto, identity);
  const wf = prover();
  const proof = await wf.prove("saltBinding", witness);
  assert.equal(proof.publicSignals.length, 1);
  assert.equal(BigInt(proof.publicSignals[0]), witness.saltCommitment);
  assert.equal(await wf.verify(proof), true);
});

test("a salt-binding proof lifted onto another commitment does not verify", { skip }, async () => {
  const crypto = await realPoseidon();
  const wf = prover();
  const proof = await wf.prove("saltBinding", await saltBindingWitness(crypto, identity));
  const tampered = { ...proof, publicSignals: [(BigInt(proof.publicSignals[0]) + 1n).toString()] };
  assert.equal(await wf.verify(tampered), false);
});

test("a credential leaf is proven well formed over the attested fields", { skip }, async () => {
  const crypto = await realPoseidon();
  const witness = await credentialWellFormedWitness(crypto, {
    identity,
    ita,
    regimeHash,
    ikId,
    attrs,
    expiresAt,
  });
  const wf = prover();
  const proof = await wf.prove("credentialWellFormed", witness);
  const publics = decodeWfPublicSignals("credentialWellFormed", proof.publicSignals);
  assert.equal(await wf.verify(proof), true);
  assert.deepEqual(publics, {
    leaf: witness.leaf,
    saltCommitment: witness.saltCommitment,
    ita,
    regimeHash,
    did: identity.did,
    attrsHash: witness.attrsHash,
    ikId,
    expiresAt,
  });
  // The attributes themselves are private: nothing in the public signals is one of them.
  for (const value of Object.values(publics)) {
    assert.notEqual(value, attrs[0]);
  }
});

test("a tampered credential public is refused by the verifier", { skip }, async () => {
  const crypto = await realPoseidon();
  const wf = prover();
  const proof = await wf.prove(
    "credentialWellFormed",
    await credentialWellFormedWitness(crypto, { identity, ita, regimeHash, ikId, attrs, expiresAt }),
  );
  const publicSignals = [...proof.publicSignals];
  publicSignals[7] = (BigInt(publicSignals[7]) + 86400n).toString(); // a later expiry
  assert.equal(await wf.verify({ ...proof, publicSignals }), false);
});

test("a leaf whose salt does not open the commitment cannot be witnessed", { skip }, async () => {
  const crypto = await realPoseidon();
  const witness = await credentialWellFormedWitness(crypto, {
    identity,
    ita,
    regimeHash,
    ikId,
    attrs,
    expiresAt,
  });
  const wf = prover();
  // The registered commitment belongs to somebody else's salt; the leaf is otherwise perfect.
  const foreign = { ...witness, saltCommitment: await crypto.h2(identity.privateSalt + 1n, 0n) };
  await assert.rejects(wf.prove("credentialWellFormed", foreign));
});

test("both pseudonym anchors are proven from one committed salt", { skip }, async () => {
  const crypto = await realPoseidon();
  const witness = await pseudonymWellFormedWitness(crypto, { identity, regimeHash, gatedContract });
  const wf = prover();
  const proof = await wf.prove("pseudonymWellFormed", witness);
  assert.equal(await wf.verify(proof), true);
  const publics = decodeWfPublicSignals("pseudonymWellFormed", proof.publicSignals);
  assert.equal(publics.pseudonym, witness.pseudonym);
  assert.equal(publics.masterPseudonym, witness.masterPseudonym);
  assert.equal(publics.saltCommitment, witness.saltCommitment);
  assert.notEqual(publics.masterPseudonym, publics.pseudonym);
});

test("a swapped master anchor is refused by the verifier", { skip }, async () => {
  const crypto = await realPoseidon();
  const wf = prover();
  const proof = await wf.prove(
    "pseudonymWellFormed",
    await pseudonymWellFormedWitness(crypto, { identity, regimeHash, gatedContract }),
  );
  const publicSignals = [...proof.publicSignals];
  publicSignals[4] = (BigInt(publicSignals[4]) + 1n).toString();
  assert.equal(await wf.verify({ ...proof, publicSignals }), false);
});

test("a pseudonym cannot be claimed against a foreign salt commitment", { skip }, async () => {
  const crypto = await realPoseidon();
  const witness = await pseudonymWellFormedWitness(crypto, { identity, regimeHash, gatedContract });
  const wf = prover();
  await assert.rejects(
    wf.prove("pseudonymWellFormed", {
      ...witness,
      saltCommitment: await crypto.h2(identity.privateSalt + 1n, 0n),
    }),
  );
});

test("an artifact that does not match its pin never reaches the prover", { skip }, async () => {
  const crypto = await realPoseidon();
  const pins = JSON.parse(readFileSync(pinsPath, "utf8")) as {
    circuits: Record<string, PinnedCircuit>;
  };
  const genuine = artifactSet(pins.circuits.wf_salt_binding);
  const wf = prover({
    saltBinding: { ...genuine, zkey: { ...genuine.zkey, sha256: `0x${"11".repeat(32)}` } },
  });
  await assert.rejects(
    wf.prove("saltBinding", await saltBindingWitness(crypto, identity)),
    /digest mismatch/,
  );
});

test("the pins file names its ceremony as development-only", { skip }, () => {
  const pins = JSON.parse(readFileSync(pinsPath, "utf8"));
  assert.equal(pins.developmentOnly, true);
  assert.equal(pins.ceremony, "DEV_SINGLE_CONTRIBUTION");
  assert.deepEqual(Object.keys(pins.circuits).sort(), ["wf_cred", "wf_pseudonym", "wf_salt_binding"]);
  // The digest covers every source the artifacts were built from, libs included, `--check`
  // never recompiles, so a pin over the eleven-line wrappers alone would miss a rewritten
  // statement entirely.
  assert.match(pins.sourcesSha256, /^0x[0-9a-f]{64}$/);
  for (const circuit of Object.values(pins.circuits) as { sha256: Record<string, string> }[]) {
    for (const digest of Object.values(circuit.sha256)) assert.match(digest, /^0x[0-9a-f]{64}$/);
  }
});

/**
 * The eight sources `build-wf.sh` digests, PARSED OUT OF THE SCRIPT rather than restated.
 *
 * A ninth lib added to `WF_SOURCES` must be covered here the moment it is added, and a list
 * copied into this file would simply be a fourth transcription to keep in step: the exact defect
 * `wf-circuits.test.ts` already greps this script to avoid.
 */
function wfSources(): readonly string[] {
  const script = readFileSync(resolve(repoRoot, "scripts/v2/build-wf.sh"), "utf8");
  const block = /^WF_SOURCES=\(\n([\s\S]*?)^\)$/m.exec(script);
  assert.ok(block, "scripts/v2/build-wf.sh must declare a WF_SOURCES array");
  return block[1].split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
}

/** `sources_digest()` in `build-wf.sh`: `shasum -a 256 <files> | shasum -a 256`, reproduced. */
function sourcesDigest(files: readonly string[]): string {
  const listing = files
    .map((file) => `${createHash("sha256").update(readFileSync(resolve(repoRoot, file))).digest("hex")}  ${file}\n`)
    .join("");
  return `0x${createHash("sha256").update(listing).digest("hex")}`;
}

test("the pinned source digest is the digest of the circuit sources AS THEY ARE NOW", { skip }, () => {
  const pins = JSON.parse(readFileSync(pinsPath, "utf8")) as { sourcesSha256: string };
  const sources = wfSources();
  assert.equal(sources.length, 8, "build-wf.sh must digest all eight well-formedness sources");

  // THE PIN WAS ONLY EVER CHECKED FOR ITS SHAPE, `/^0x[0-9a-f]{64}$/` above passes just as
  // happily over a digest taken before a statement was rewritten. `build-wf.sh --check` does
  // compare it, but nothing in any test suite ran that, so an edited circuit lib and a stale
  // zkey coexisted quietly: the SDK proves and verifies against artifacts that no longer
  // implement the source in the tree, and every test here passes because both sides are stale
  // together. Recomputing it is what turns that into a failure somebody sees.
  assert.equal(
    pins.sourcesSha256,
    sourcesDigest(sources),
    "circuit sources changed since these artifacts were built, re-run scripts/v2/build-wf.sh",
  );
});
