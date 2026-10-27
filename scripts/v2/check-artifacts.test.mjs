import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { checkArtifactBundle } from "./check-artifacts.mjs";
import { circuitSourceDigest, toolchainVersions } from "./circuit-provenance.mjs";
import { readDevelopmentBeacon } from "./dev-beacon.mjs";
import { rewriteVerifier } from "./verifier-rewrite.mjs";

// The fixture root carries its own circuit source, phase-1 file and resolved snarkjs, so the
// provenance record is a property of the fixture rather than of the developer's machine. Only the
// circom version comes from the real toolchain: there is no per-root circom to point at, and the
// check is precisely "did THIS toolchain build these artifacts".
const PROVENANCE_FILES = Object.freeze({
  "circuits/src/v2/session.circom": 'include "./lib/gap_session.circom";\n',
  "circuits/src/v2/lib/gap_session.circom": "template GapSession() {}\n",
  "powersOfTau28_hez_final_16.ptau": "ptau",
  "circuits/node_modules/snarkjs/package.json": '{"version":"0.7.5"}\n',
  "scripts/v2/lib/dev-beacon.sh":
    `DEV_BEACON_HEX="${"b".repeat(64)}"\nDEV_BEACON_ITERATIONS=7\n`,
});

const FILES = Object.freeze({
  r1csSha256: ["circuits/build/v2/session.r1cs", "r1cs"],
  wasmSha256: ["circuits/build/v2/session_js/session.wasm", "wasm"],
  zkeySha256: ["circuits/keys/v2/session_final.zkey", "zkey"],
  verificationKeySha256: [
    "circuits/keys/v2/verification_key.json",
    '{"protocol":"groth16","vk_delta_2":[["1","2"]]}',
  ],
  solidityVerifierSha256: [
    "contracts/src/v2/SessionVerifier.sol",
    rewriteVerifier("pragma solidity >=0.7.0 <0.9.0;\ncontract Groth16Verifier {\n}\n", {
      contractName: "SessionVerifier",
    }),
  ],
  proofFixtureSha256: ["contracts/test/fixtures/v2/proof.json", "{}\n"],
  publicFixtureSha256: ["contracts/test/fixtures/v2/public.json", "[]\n"],
  scenarioFixtureSha256: ["contracts/test/fixtures/v2/scenario.json", "{}\n"],
});

const digest = (contents) =>
  createHash("sha256").update(contents).digest("hex");

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "gap-artifact-test-"));
  for (const [relative, contents] of Object.entries(PROVENANCE_FILES)) {
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, contents);
  }
  const manifest = {
    schemaVersion: 2,
    profile: "gap-v2-local-development",
    publicInputs: 19,
    constraints: 46000,
    classification: "local-development-only",
    circuitSourceSha256: await circuitSourceDigest(
      path.join(root, "circuits/src/v2/session.circom"),
      path.join(root, "circuits/src"),
    ),
    ptauSha256: digest(PROVENANCE_FILES["powersOfTau28_hez_final_16.ptau"]),
    ...(await toolchainVersions({ circuitsDir: path.join(root, "circuits") })),
    setupClosure: await readDevelopmentBeacon(root).then(({ hex, iterations }) => ({
      kind: "beacon",
      beaconHex: hex,
      beaconIterations: Number(iterations),
    })),
  };
  for (const [field, [relative, contents]] of Object.entries(FILES)) {
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, contents);
    manifest[field] = digest(contents);
  }
  const manifestPath = path.join(
    root,
    "circuits/keys/v2/local-artifact-manifest.json",
  );
  await writeFile(manifestPath, JSON.stringify(manifest));
  return root;
}

test("accepts a zkey-derived key and normalized generated verifier", async () => {
  const root = await fixture();
  try {
    await checkArtifactBundle({
      root,
      exportArtifacts: async ({ verificationKey, verifier }) => {
        await writeFile(
          verificationKey,
          '{\n  "vk_delta_2": [["1", "2"]], "protocol": "groth16"\n}\n',
        );
        await writeFile(
          verifier,
          "pragma solidity >=0.7.0 <0.9.0;\r\ncontract Groth16Verifier {\r\n}\r\n",
        );
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects individually pinned artifacts when the zkey derives another key", async () => {
  const root = await fixture();
  try {
    await assert.rejects(
      checkArtifactBundle({
        root,
        exportArtifacts: async ({ verificationKey, verifier }) => {
          await writeFile(
            verificationKey,
            '{"protocol":"groth16","vk_delta_2":[["9","9"]]}',
          );
          await writeFile(
            verifier,
            "pragma solidity >=0.7.0 <0.9.0;\ncontract Groth16Verifier {\n}\n",
          );
        },
      }),
      /verification_key\.json was not derived from session_final\.zkey/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a missing zkey manifest pin before invoking snarkjs", async () => {
  const root = await fixture();
  let exported = false;
  try {
    const manifestPath = path.join(
      root,
      "circuits/keys/v2/local-artifact-manifest.json",
    );
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    delete manifest.zkeySha256;
    await writeFile(manifestPath, JSON.stringify(manifest));
    await assert.rejects(
      checkArtifactBundle({
        root,
        exportArtifacts: async () => {
          exported = true;
        },
      }),
      /manifest field zkeySha256 is missing or invalid/,
    );
    assert.equal(exported, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ── provenance ────────────────────────────────────────────────────────────────────────────────
// The digest fields prove the bundle agrees with ITSELF. These prove it agrees with the circuit,
// the phase-1 file and the toolchain it claims to have come from, the questions a substituted
// zkey answers cleanly under the digest checks alone.

async function rejectsWithMutatedManifest(mutate, pattern) {
  const root = await fixture();
  try {
    const manifestPath = path.join(
      root,
      "circuits/keys/v2/local-artifact-manifest.json",
    );
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    mutate(manifest);
    await writeFile(manifestPath, JSON.stringify(manifest));
    await assert.rejects(
      checkArtifactBundle({ root, exportArtifacts: async () => {} }),
      pattern,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("rejects a manifest with no provenance record at all", async () => {
  await rejectsWithMutatedManifest(
    (manifest) => {
      manifest.schemaVersion = 1;
    },
    /schemaVersion is 1, expected 2/,
  );
});

test("rejects artifacts built from a different circuit source", async () => {
  await rejectsWithMutatedManifest(
    (manifest) => {
      manifest.circuitSourceSha256 = "f".repeat(64);
    },
    /circuitSourceSha256 does not match the committed circuit source closure/,
  );
});

test("rejects artifacts built against a different phase-1 file", async () => {
  await rejectsWithMutatedManifest(
    (manifest) => {
      manifest.ptauSha256 = "f".repeat(64);
    },
    /ptauSha256 does not match the local phase-1 file/,
  );
});

test("rejects artifacts built by a different toolchain", async () => {
  await rejectsWithMutatedManifest(
    (manifest) => {
      manifest.snarkjsVersion = "0.0.1";
    },
    /snarkjsVersion is "0\.0\.1" in the manifest but "[^"]+" locally/,
  );
});

test("rejects a bundle that will not say how phase 2 was closed", async () => {
  await rejectsWithMutatedManifest(
    (manifest) => {
      delete manifest.setupClosure;
    },
    /setupClosure does not record a beacon close/,
  );
});

test("rejects a recorded close the build scripts did not perform", async () => {
  await rejectsWithMutatedManifest(
    (manifest) => {
      manifest.setupClosure.beaconHex = "a".repeat(64);
    },
    /records a close that did not happen/,
  );
  await rejectsWithMutatedManifest(
    (manifest) => {
      manifest.setupClosure.beaconIterations = 99;
    },
    /setupClosure\.beaconIterations does not match the build scripts/,
  );
});

test("refuses to pass when the beacon definition it must check against is gone", async () => {
  const root = await fixture();
  try {
    await rm(path.join(root, "scripts/v2/lib/dev-beacon.sh"));
    await assert.rejects(
      checkArtifactBundle({ root, exportArtifacts: async () => {} }),
      /cannot confirm the recorded phase-2 close/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
