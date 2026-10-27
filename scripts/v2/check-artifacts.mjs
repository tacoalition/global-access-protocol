#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdtemp,
  readFile,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { comparableVerifier } from "./verifier-rewrite.mjs";
import { circuitSourceDigest, toolchainVersions } from "./circuit-provenance.mjs";
import { readDevelopmentBeacon } from "./dev-beacon.mjs";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_ROOT = path.resolve(SCRIPT_DIR, "../..");

const ARTIFACTS = Object.freeze([
  ["r1csSha256", "circuits/build/v2/session.r1cs"],
  ["wasmSha256", "circuits/build/v2/session_js/session.wasm"],
  ["zkeySha256", "circuits/keys/v2/session_final.zkey"],
  ["verificationKeySha256", "circuits/keys/v2/verification_key.json"],
  ["solidityVerifierSha256", "contracts/src/v2/SessionVerifier.sol"],
  ["proofFixtureSha256", "contracts/test/fixtures/v2/proof.json"],
  ["publicFixtureSha256", "contracts/test/fixtures/v2/public.json"],
  ["scenarioFixtureSha256", "contracts/test/fixtures/v2/scenario.json"],
]);

export function artifactPaths(root = DEFAULT_ROOT) {
  return {
    root,
    circuitsDir: path.join(root, "circuits"),
    manifest: path.join(root, "circuits/keys/v2/local-artifact-manifest.json"),
    zkey: path.join(root, "circuits/keys/v2/session_final.zkey"),
    verificationKey: path.join(root, "circuits/keys/v2/verification_key.json"),
    verifier: path.join(root, "contracts/src/v2/SessionVerifier.sol"),
  };
}

export async function digestFile(file) {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonicalJson(child)]),
    );
  }
  return value;
}

export function normalizeVerificationKey(contents) {
  return JSON.stringify(canonicalJson(JSON.parse(contents)));
}

// Both sides go through the SAME rewrite the build applies, so a committed verifier (already
// rewritten) and a freshly-exported one (not yet) land in one comparable form. The rewrite is
// idempotent, which is what makes applying it to the committed side safe.
export function normalizeSolidityVerifier(contents) {
  return comparableVerifier(contents, { contractName: "SessionVerifier" });
}

function defaultExporter({ paths, verificationKey, verifier }) {
  const common = ["--dir", paths.circuitsDir, "exec", "snarkjs", "zkey", "export"];
  execFileSync(
    "pnpm",
    [...common, "verificationkey", paths.zkey, verificationKey],
    { stdio: "pipe" },
  );
  execFileSync(
    "pnpm",
    [...common, "solidityverifier", paths.zkey, verifier],
    { stdio: "pipe" },
  );
}

function invalid(errors) {
  return new Error(
    [
      "GAP v2 local proof artifacts are incoherent:",
      ...errors.map((error) => `  - ${error}`),
      'Run "make build" to generate one coherent local artifact bundle.',
    ].join("\n"),
  );
}

// The manifest's INPUT record. Digest fields prove the bundle is internally coherent; these prove
// it came from the committed circuit, the verified phase-1 file, and the pinned toolchain. Without
// them a bundle rebuilt from a quietly-edited circuit is indistinguishable from the reviewed one.
async function checkProvenance({ root, manifest, errors }) {
  if (manifest.schemaVersion !== 2) {
    errors.push(
      `manifest schemaVersion is ${manifest.schemaVersion}, expected 2 (the provenance record). ` +
        `Run "make build" to regenerate it.`,
    );
    return;
  }

  const expectedSource = await circuitSourceDigest(
    path.join(root, "circuits/src/v2/session.circom"),
    path.join(root, "circuits/src"),
  ).catch((error) => `unreadable: ${error.message}`);
  if (manifest.circuitSourceSha256 !== expectedSource) {
    errors.push(
      "circuitSourceSha256 does not match the committed circuit source closure: the artifacts " +
        "were built from a different circuit than the one in the tree",
    );
  }

  try {
    const ptau = await digestFile(path.join(root, "powersOfTau28_hez_final_16.ptau"));
    if (manifest.ptauSha256 !== ptau) {
      errors.push("ptauSha256 does not match the local phase-1 file");
    }
  } catch {
    // A developer who has not fetched the ptau still gets a coherent-bundle check; the digest is
    // pinned in the manifest and re-verified by scripts/v2/lib/fetch-ptau.sh at build time.
    if (!/^[0-9a-f]{64}$/.test(manifest.ptauSha256 ?? "")) {
      errors.push("manifest field ptauSha256 is missing or invalid");
    }
  }

  try {
    const versions = await toolchainVersions({ circuitsDir: path.join(root, "circuits") });
    for (const [field, actual] of Object.entries(versions)) {
      if (manifest[field] !== actual) {
        errors.push(
          `${field} is "${manifest[field]}" in the manifest but "${actual}" locally: this ` +
            `toolchain did not produce these artifacts`,
        );
      }
    }
  } catch (error) {
    errors.push(`could not read the local toolchain versions: ${error.message}`);
  }

  const closure = manifest.setupClosure;
  if (!closure || closure.kind !== "beacon") {
    errors.push(
      "setupClosure does not record a beacon close. A development bundle whose phase 2 was " +
        "closed some other way is not reproducible, and the manifest must say so.",
    );
    return;
  }
  // Deliberately NOT swallowed. An unreadable beacon file makes the strongest provenance check a
  // silent no-op, which is worse than not having it: the manifest's recorded close would go
  // unchecked precisely when the definition it must agree with has gone missing.
  let beacon;
  try {
    beacon = await readDevelopmentBeacon(root);
  } catch (error) {
    errors.push(
      `cannot confirm the recorded phase-2 close: ${error.message}`,
    );
    return;
  }
  if (closure.beaconHex !== beacon.hex) {
    errors.push(
      "setupClosure.beaconHex is not the value the build scripts use; the manifest records a " +
        "close that did not happen",
    );
  }
  if (closure.beaconIterations !== Number(beacon.iterations)) {
    errors.push("setupClosure.beaconIterations does not match the build scripts");
  }
}

export async function checkArtifactBundle({
  root = DEFAULT_ROOT,
  exportArtifacts = defaultExporter,
} = {}) {
  const paths = artifactPaths(root);
  let manifest;
  try {
    manifest = JSON.parse(await readFile(paths.manifest, "utf8"));
  } catch (error) {
    throw invalid([`cannot read manifest ${paths.manifest}: ${error.message}`]);
  }

  const errors = [];
  for (const [field, relative] of ARTIFACTS) {
    const expected = manifest[field];
    const expectedIsValid =
      typeof expected === "string" && /^[0-9a-f]{64}$/i.test(expected);
    if (!expectedIsValid) {
      errors.push(`manifest field ${field} is missing or invalid`);
    }
    const file = path.join(root, relative);
    try {
      const actual = await digestFile(file);
      if (expectedIsValid && actual !== expected.toLowerCase()) {
        errors.push(`${relative} digest does not match ${field}`);
      }
    } catch (error) {
      errors.push(`required artifact ${relative} is unavailable: ${error.message}`);
    }
  }
  await checkProvenance({ root, manifest, errors });
  if (errors.length > 0) throw invalid(errors);

  const temporary = await mkdtemp(path.join(tmpdir(), "gap-v2-artifacts-"));
  const exportedVerificationKey = path.join(temporary, "verification_key.json");
  const exportedVerifier = path.join(temporary, "SessionVerifier.sol");
  try {
    try {
      await exportArtifacts({
        paths,
        verificationKey: exportedVerificationKey,
        verifier: exportedVerifier,
      });
    } catch (error) {
      throw invalid([`could not derive verifier artifacts from zkey: ${error.message}`]);
    }

    const [committedKey, derivedKey, committedVerifier, derivedVerifier] =
      await Promise.all([
        readFile(paths.verificationKey, "utf8"),
        readFile(exportedVerificationKey, "utf8"),
        readFile(paths.verifier, "utf8"),
        readFile(exportedVerifier, "utf8"),
      ]);
    if (normalizeVerificationKey(committedKey) !== normalizeVerificationKey(derivedKey)) {
      errors.push("verification_key.json was not derived from session_final.zkey");
    }
    if (
      normalizeSolidityVerifier(committedVerifier) !==
      normalizeSolidityVerifier(derivedVerifier)
    ) {
      errors.push("SessionVerifier.sol was not derived from session_final.zkey");
    }
    if (errors.length > 0) throw invalid(errors);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }

  return { manifest, paths };
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
  checkArtifactBundle()
    .then(() => console.log("GAP v2 local proof artifacts are coherent."))
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
}
