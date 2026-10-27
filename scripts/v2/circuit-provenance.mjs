// WHAT A DIGEST OF THE .r1cs DOES NOT TELL YOU.
//
// The manifest already pins the compiled artifacts, which catches "someone shipped a verifier that
// does not match the committed r1cs". It cannot catch the question an auditor actually asks: what
// did this come FROM? A compiled r1cs is a fixed point of (circuit source, circom version,
// include closure), change any one and the digest moves, but the manifest cannot say WHICH moved,
// and it cannot say anything at all about the phase-1 file or the phase-2 close, neither of which
// appears in the r1cs.
//
// So the manifest carries the inputs too. `circuitSourceSha256` folds the transitive local include
// closure: the third-party circomlib templates under node_modules are pinned by the lockfile, not
// here, and mixing the two would make the digest move on every unrelated dependency bump.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FETCH_CIRCOM = path.join(path.dirname(fileURLToPath(import.meta.url)), "lib/fetch-circom.sh");

const INCLUDE = /^\s*include\s+"([^"]+)"\s*;/gm;

/**
 * Transitive closure of LOCAL includes, in repository-relative sorted order.
 * A relative include resolves against the including file; anything that escapes the given source
 * root (circomlib, node_modules) is deliberately not followed.
 */
export async function includeClosure(entry, sourceRoot) {
  const seen = new Map();
  const pending = [path.resolve(entry)];
  while (pending.length > 0) {
    const file = pending.pop();
    if (seen.has(file)) continue;
    const relative = path.relative(sourceRoot, file);
    if (relative.startsWith("..") || path.isAbsolute(relative)) continue;
    let source;
    try {
      source = await readFile(file, "utf8");
    } catch {
      continue;
    }
    seen.set(file, source);
    for (const match of source.matchAll(INCLUDE)) {
      pending.push(path.resolve(path.dirname(file), match[1]));
    }
  }
  return [...seen.entries()]
    .map(([file, source]) => [path.relative(sourceRoot, file), source])
    .sort(([left], [right]) => left.localeCompare(right));
}

/** One digest over the closure, binding filenames as well as contents. */
export async function circuitSourceDigest(entry, sourceRoot) {
  const fold = createHash("sha256");
  for (const [relative, source] of await includeClosure(entry, sourceRoot)) {
    fold.update(relative).update("\0");
    fold.update(createHash("sha256").update(source).digest()).update("\0");
  }
  return fold.digest("hex");
}

/**
 * The toolchain that produced the artifacts. snarkjs is read from the resolved package rather than
 * `snarkjs --version`, which prints its banner and exits non-zero; circom has no package to read,
 * so its version comes from the binary. Recorded verbatim rather than parsed into parts: the
 * point is to reproduce a build, and an auditor comparing strings wants the string.
 *
 * THE BINARY IS THE ONE THE BUILD USED, resolved by the same `ensure_circom` the build scripts call.
 * This once ran whatever `circom` was on PATH while the build compiled with the pinned binary, so a
 * machine with another circom installed recorded a compiler that built nothing, and a machine with
 * none, a CI runner, could not record anything.
 */
export async function toolchainVersions({ circuitsDir }) {
  let circom;
  try {
    const binary = execFileSync(
      "bash",
      ["-c", '. "$1" && ensure_circom "${GAP_CIRCOM_CACHE:-}"', "bash", FETCH_CIRCOM],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();
    circom = execFileSync(binary, ["--version"], { encoding: "utf8", stdio: "pipe" })
      .split("\n")[0]
      .trim();
  } catch (error) {
    throw new Error(`could not read circom --version: ${error.message}`);
  }
  if (!/^circom compiler \d/.test(circom)) {
    throw new Error(`unexpected circom --version output: ${circom}`);
  }

  const manifest = path.join(circuitsDir, "node_modules/snarkjs/package.json");
  let snarkjs;
  try {
    snarkjs = JSON.parse(await readFile(manifest, "utf8")).version;
  } catch (error) {
    throw new Error(`could not read the resolved snarkjs version from ${manifest}: ${error.message}`);
  }
  if (typeof snarkjs !== "string" || !/^\d+\.\d+\.\d+/.test(snarkjs)) {
    throw new Error(`unexpected snarkjs version in ${manifest}: ${snarkjs}`);
  }

  return { circomVersion: circom.replace(/^circom compiler /, ""), snarkjsVersion: snarkjs };
}

/** How phase 2 was closed. A development build says so here, in the artifact's own record. */
export function developmentClosure({ hex, iterations }) {
  return {
    kind: "beacon",
    beaconHex: hex,
    beaconIterations: Number(iterations),
    reproducible: true,
    note:
      "Closed on a value published in this repository, so the trapdoor is recoverable by any " +
      "reader. Development artifacts only; the production path is scripts/v2/wf-ceremony.sh.",
  };
}
