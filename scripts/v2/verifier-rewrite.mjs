#!/usr/bin/env node
//
// THE ONE DEFINITION of how a snarkjs-exported verifier becomes a committed one.
//
// This used to live twice: as a `sed` expression inside each build script, and again as a
// `normalizeSolidityVerifier` regex inside check-artifacts.mjs, which had to *undo* the sed in
// order to compare a committed verifier against a freshly-exported one. Two spellings of one
// transform is the failure mode where the checker keeps agreeing with a build that drifted.
// Both callers now come here.
//
// The rewrite is idempotent by construction: every pattern below matches only the snarkjs output
// shape, so re-running it over an already-rewritten file is a no-op. check-artifacts.mjs relies
// on that: it applies the rewrite to BOTH sides before comparing.
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPORTED_PRAGMA = /pragma solidity >=0\.7\.0 <0\.9\.0;/g;
const PINNED_PRAGMA = "pragma solidity 0.8.20;";
const EXPORTED_CONTRACT = /contract Groth16Verifier\s*\{/;

// Why every development verifier says so in its own bytecode: a verifier is the one artifact that
// outlives the machine that built it. `LOCAL_DEVELOPMENT_ARTIFACT()` is callable on chain, so
// anyone pointed at a deployment can ask it directly instead of trusting a filename or a README.
// Read the negative carefully, absence proves nothing, because a pre-marker or hand-rolled
// artifact is also unmarked. Presence is the only load-bearing direction: it is a confession.
export const DEVELOPMENT_MARKER = "LOCAL_DEVELOPMENT_ARTIFACT";

function developmentNotice(ceremonyScript) {
  return [
    "    /// @notice This verifier came from a DEVELOPMENT setup closed on a value published in",
    "    ///         the repository. Its trapdoor is recoverable by anyone who can read the build",
    `    ///         script, so proofs it accepts are NOT sound. ${ceremonyScript}`,
    "    ///         is the production path. Absence of this flag proves nothing; only a",
    "    ///         ceremony transcript does.",
    `    bool public constant ${DEVELOPMENT_MARKER} = true;`,
  ].join("\n");
}

/**
 * @param {string} source        verifier text, exported or already rewritten
 * @param {object} options
 * @param {string} options.contractName   what the contract should be called
 * @param {boolean} [options.development] stamp the development confession (default true)
 * @param {string} [options.ceremonyScript] the production path named in the notice
 * @returns {string} the committed form
 */
export function rewriteVerifier(source, {
  contractName,
  development = true,
  ceremonyScript = "scripts/v2/wf-ceremony.sh",
}) {
  if (!contractName) throw new Error("rewriteVerifier requires a contractName");
  const header = development
    ? `contract ${contractName} {\n${developmentNotice(ceremonyScript)}`
    : `contract ${contractName} {`;
  return source
    .replace(/\r\n?/g, "\n")
    .replace(EXPORTED_PRAGMA, PINNED_PRAGMA)
    .replace(EXPORTED_CONTRACT, header);
}

/** Line-trimmed comparison form. Whitespace at end of line is not provenance. */
export function comparableVerifier(source, options) {
  return rewriteVerifier(source, options)
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .trimEnd();
}

export async function rewriteVerifierFile(file, options) {
  const source = await readFile(file, "utf8");
  const rewritten = rewriteVerifier(source, options);
  await writeFile(file, rewritten);
  return rewritten;
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
  const [file, contractName, development] = process.argv.slice(2);
  if (!file || !contractName) {
    console.error(
      "usage: verifier-rewrite.mjs <file> <ContractName> [development|production]",
    );
    process.exitCode = 1;
  } else {
    rewriteVerifierFile(file, {
      contractName,
      development: development !== "production",
    })
      .then(() => console.log(`rewrote ${path.basename(file)} as ${contractName}`))
      .catch((error) => {
        console.error(error.message);
        process.exitCode = 1;
      });
  }
}
