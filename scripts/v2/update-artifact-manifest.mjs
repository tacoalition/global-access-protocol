#!/usr/bin/env node
import { readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  DEFAULT_ROOT,
  artifactPaths,
  digestFile,
} from "./check-artifacts.mjs";
import {
  circuitSourceDigest,
  developmentClosure,
  toolchainVersions,
} from "./circuit-provenance.mjs";
import { readDevelopmentBeacon } from "./dev-beacon.mjs";
import { digestOfCode } from "./deployed-bytecode.mjs";
import { locallyBuiltRuntimeCode } from "./verifier-binding.mjs";

const DIGESTS = Object.freeze({
  r1csSha256: "circuits/build/v2/session.r1cs",
  wasmSha256: "circuits/build/v2/session_js/session.wasm",
  zkeySha256: "circuits/keys/v2/session_final.zkey",
  verificationKeySha256: "circuits/keys/v2/verification_key.json",
  solidityVerifierSha256: "contracts/src/v2/SessionVerifier.sol",
  proofFixtureSha256: "contracts/test/fixtures/v2/proof.json",
  publicFixtureSha256: "contracts/test/fixtures/v2/public.json",
  scenarioFixtureSha256: "contracts/test/fixtures/v2/scenario.json",
});


/**
 * Read the constraint count and public-input count out of the r1cs header.
 *
 * The r1cs format puts a header section first: magic "r1cs", version, section count, then the
 * header section whose body is field-size, prime, nWires, nPubOut, nPubIn, nPrvIn, nLabels,
 * nConstraints. We want nConstraints and the public total, so we read the header and stop.
 */
async function r1csShape(r1csPath) {
  const buf = await readFile(r1csPath);
  if (buf.subarray(0, 4).toString("ascii") !== "r1cs") {
    throw new Error(`not an r1cs file: ${r1csPath}`);
  }
  // 4 magic + 4 version + 4 sectionCount, then sections: 4 type + 8 size + body
  let off = 12;
  const sectionCount = buf.readUInt32LE(8);
  for (let i = 0; i < sectionCount; i++) {
    const type = buf.readUInt32LE(off);
    const size = Number(buf.readBigUInt64LE(off + 4));
    const body = off + 12;
    if (type === 1) {
      const fieldSize = buf.readUInt32LE(body);
      let p = body + 4 + fieldSize;        // skip the prime
      p += 4;                              // nWires
      const nPubOut = buf.readUInt32LE(p); p += 4;
      const nPubIn = buf.readUInt32LE(p); p += 4;
      p += 4;                              // nPrvIn
      p += 8;                              // nLabels
      const nConstraints = buf.readUInt32LE(p);
      return { constraints: nConstraints, publicInputs: nPubOut + nPubIn };
    }
    off = body + size;
  }
  throw new Error(`no header section in ${r1csPath}`);
}

export async function updateArtifactManifest(root = DEFAULT_ROOT) {
  const { manifest: manifestPath } = artifactPaths(root);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  for (const [field, relative] of Object.entries(DIGESTS)) {
    manifest[field] = await digestFile(path.join(root, relative));
  }

  // The inputs, not only the outputs. See circuit-provenance.mjs for why an r1cs digest alone
  // cannot answer "what did this come from".
  // THE SHAPE OF THE CIRCUIT, read from the r1cs rather than carried forward. These two fields were
  // written by nothing and checked by nothing, so they survived two circuit changes untouched: the
  // manifest still said 55,877 constraints while the build asserted 59,143. A provenance file whose
  // numbers are stale is worse than one without them, because it reads as a record.
  Object.assign(manifest, await r1csShape(path.join(root, "circuits/build/v2/session.r1cs")));

  manifest.schemaVersion = 2;
  manifest.circuitSourceSha256 = await circuitSourceDigest(
    path.join(root, "circuits/src/v2/session.circom"),
    path.join(root, "circuits/src"),
  );
  manifest.ptauSha256 = await digestFile(
    path.join(root, "powersOfTau28_hez_final_16.ptau"),
  );
  Object.assign(manifest, await toolchainVersions({
    circuitsDir: path.join(root, "circuits"),
  }));
  manifest.setupClosure = developmentClosure(await readDevelopmentBeacon(root));
  // The only field that binds to something OUTSIDE this repository. A source digest cannot see a
  // verifier compiled with other settings, or one built from a circuit that has since changed: 
  // both of which have happened here.
  // NOT A PIN, and worth saying so where it is written. Nothing in `check-artifacts.mjs` reads this
  // field; the two things that do are the two the README lists as reached by no target. It is also
  // not reproducible: a cold clone's `make build` rewrites it, because solc embeds metadata that
  // varies by environment. Treat it as a note about one machine, not as a binding on the deployed
  // verifier.
  manifest.deployedBytecodeSha256 = digestOfCode(locallyBuiltRuntimeCode("SessionVerifier"));

  const temporary = `${manifestPath}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o644,
  });
  await rename(temporary, manifestPath);
  return manifest;
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
  updateArtifactManifest()
    .then(() => console.log("Updated GAP v2 local artifact manifest."))
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
}
