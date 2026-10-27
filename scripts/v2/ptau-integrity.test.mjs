/**
 * THE PHASE-1 FILE IS VERIFIED BEFORE ANY CEREMONY IS BUILT ON IT.
 *
 * A phase-2 ceremony with three contributors and a closing beacon, run over a SUBSTITUTED phase-1
 * file, is worth nothing: the trapdoor everyone contributed to destroying was never the one in
 * play. Both build scripts previously fetched the ptau with `curl -sL`: no `-f`, so an HTTP error
 * page lands on disk as the ptau, and no digest, so a substitution is invisible.
 *
 * The pin is UPSTREAM'S OWN value (the snarkjs README's blake2b for the 2^16 file), and the local
 * copy was verified against it before it was written down.
 */
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

// `fileURLToPath`, not `.pathname`: a file URL percent-encodes, so a checkout under a path with
// a space resolves to ".../space%20test/..." and every read here fails ENOENT. Four other
// scripts in this directory already do it this way.
const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const LIB = join(ROOT, "scripts/v2/lib/fetch-ptau.sh");

const runShell = (script) =>
  execFileSync("bash", ["-c", `. ${JSON.stringify(LIB)}; ${script}`],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

test("the pinned digests are upstream's published values, not ours", () => {
  const source = readFileSync(LIB, "utf8");
  // The 2^16 row of the snarkjs README's prepared-phase2 table. If this constant is ever
  // regenerated from a local file rather than copied from upstream, the provenance link is gone
  // and this guard becomes a checksum of whatever we happened to download.
  assert.match(source, /PTAU_BLAKE2B="6a6277a2f74e1073601b4f9fed6e1e55/);
  assert.match(source, /PTAU_SHA256="[0-9a-f]{64}"/);
  assert.match(source, /snarkjs#7-prepare-phase-2/, "the pin must cite where it came from");
});

test("a substituted phase-1 file is refused AND deleted", () => {
  // Deleting matters: a rejected artifact left on disk is one the next run finds present and
  // skips re-fetching, so the failure would launder itself into a pass.
  const fake = join(tmpdir(), `gap-ptau-fake-${process.pid}.ptau`);
  writeFileSync(fake, "<html>404 Not Found</html>");
  assert.throws(
    () => runShell(`verify_ptau ${JSON.stringify(fake)} "fake"`),
    "an HTTP error page must not pass as a phase-1 file",
  );
  assert.equal(existsSync(fake), false, "the rejected file must not be left on disk");
  rmSync(fake, { force: true });
});

test("neither build script fetches the ptau without verifying it", () => {
  for (const script of ["scripts/v2/build.sh", "scripts/v2/build-wf.sh"]) {
    const source = readFileSync(join(ROOT, script), "utf8");
    assert.doesNotMatch(
      source, /curl\s+-sL\s+-o\s+"\$PTAU"/,
      `${script} must not fetch the ptau with an unchecked, non-failing curl`,
    );
    assert.match(source, /ensure_ptau/, `${script} must fetch through the verifying helper`);
  }
});
