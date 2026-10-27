// DOCUMENTATION THAT CONTRADICTS THE CODE, CAUGHT MECHANICALLY.
//
// Five independent reviews of this repository produced about forty-five findings. Roughly half were
// one shape: a document or comment asserting something about the code that had stopped being true.
// Not arguments that went stale: those held up fine, but CHECKABLE claims: a path, a command, a
// number, a promise that something is verified elsewhere.
//
// A review finds an instance. Only a check prevents the class. These are the four patterns those
// findings actually took, each one reduced to something a machine can decide:
//
//   1. a cited file path that does not exist
//   2. a named `make` target the Makefile does not have
//   3. a constraint count that disagrees with the build's own assertion
//   4. "asserted/checked by X" where X has no caller outside a test
//
// Scope is deliberate. This does not try to understand prose; it extracts claims with a syntax and
// verifies those. Anything it cannot decide, it leaves alone: a drift check that cries wolf gets
// disabled, and then it checks nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");

/** Files whose prose makes claims about this repository. */
// SECURITY.md was added later and was NOT on this list, so the first version of it shipped a dead
// `docs/UNWIRED.md` citation that this very check exists to catch. Root-level prose counts.
const PROSE = ["README.md", "DEVELOPMENT.md", "CONTRIBUTING.md", "SECURITY.md",
  ...readdirSync(join(ROOT, "docs")).filter((f) => f.endsWith(".md")).map((f) => `docs/${f}`)];

/** Source files whose COMMENTS make the same kind of claim. */
function sources() {
  const out = [];
  const skip = new Set(["node_modules", "lib", "build", "dist", "keys", ".git", "out", "cache", "broadcast"]);
  const walk = (rel) => {
    for (const entry of readdirSync(join(ROOT, rel))) {
      if (skip.has(entry)) continue;
      const r = join(rel, entry);
      if (statSync(join(ROOT, r)).isDirectory()) walk(r);
      else if (/\.(sol|ts|mjs|js|circom|sh)$/.test(entry) && !/\.test\.|\.t\.sol$/.test(entry)) out.push(r);
    }
  };
  for (const d of ["contracts/src", "contracts/script", "packages", "circuits/src", "circuits/scripts", "scripts"]) {
    if (existsSync(join(ROOT, d))) walk(d);
  }
  return out;
}

/**
 * A claim may say a thing lives elsewhere. That is not drift: it is the honest form, and this tree
 * needs it, because its contracts cite a specification that is not distributed here.
 */
/** Build outputs, cited by name. Absent until the build that writes them has run. */
const GENERATED = new Set(["pins.json"]);

const ELSEWHERE = /\(full stack[^)]*\)|not in this repository|full stack, not in/i;
const nearby = (text, index) => text.slice(Math.max(0, index - 160), index + 160);

test("every cited file path exists, or says it does not live here", () => {
  const repoFiles = new Set();
  const collect = (rel) => {
    for (const entry of readdirSync(join(ROOT, rel))) {
      if (["node_modules", ".git", "out", "cache", "build"].includes(entry)) continue;
      const r = join(rel, entry);
      if (statSync(join(ROOT, r)).isDirectory()) collect(r);
      else repoFiles.add(entry);
    }
  };
  collect(".");
  const bad = [];
  for (const file of [...PROSE, ...sources()]) {
    const text = read(file);
    for (const m of text.matchAll(/`([A-Za-z0-9_][A-Za-z0-9_/.-]*\.(?:sol|ts|mjs|js|circom|sh|json|md))`/g)) {
      const cited = m[1];
      if (ELSEWHERE.test(nearby(text, m.index))) continue;
      // THE TEST IS EXISTENCE, NOT LOCATION. A citation is usually shorthand, 
      // `gap-sdk/metadata.ts` for `packages/gap-sdk/src/metadata.ts`, and demanding exact paths
      // would flag correct references and get this check switched off. What actually drifted in
      // every real instance was a file that is not in the tree AT ALL.
      // A path under a build output is GENERATED, absent until the build that makes it has run,
      // and citing it is correct. Checking it would make this test depend on build state.
      if (/(^|\/)(build|out|dist|cache|deployments)\//.test(cited)) continue;
      // A DEPLOYMENT ARTIFACT IS GENERATED TOO, and these are cited by bare filename as often as
      // by path. They do not exist in a fresh clone, only after a deploy, so requiring them made
      // this check fail on a clean checkout while passing on the machine that wrote the docs. That
      // is the cry-wolf failure the header warns about, found by running the suite from a clone.
      // The suffix admits digits: the first version of this pattern did not, so it exempted
      // `31337-dex.json` and still failed a clean clone on `31337-v2.json`, the main deployment.
      if (/^3\d{4}(-[a-z0-9-]+)?\.json$/.test(cited)) continue;
      // `pins.json` is the same generated artifact named without its directory.
      if (GENERATED.has(cited)) continue;
      if (!repoFiles.has(cited.split("/").pop())) bad.push(`${file}: ${cited}`);
    }
  }
  assert.deepEqual(bad, [], `cited paths that do not exist (mark them "(full stack, not in this repository)" if they live elsewhere):\n  ${bad.join("\n  ")}`);
});

test("every `make` target named in prose or comments exists", () => {
  const targets = new Set([...read("Makefile").matchAll(/^([a-z][a-z0-9-]*):/gm)].map((m) => m[1]));
  const bad = [];
  for (const file of [...PROSE, ...sources()]) {
    const text = read(file);
    // ONLY INSIDE BACKTICKS, or as a line in a fenced block. "make that claim" is English, and a
    // check that flags prose is a check somebody turns off.
    for (const m of text.matchAll(/`make ([a-z][a-z0-9-]*)[^`]*`|^\s*make ([a-z][a-z0-9-]*)\b/gm)) {
      const target = m[1] ?? m[2];
      if (!targets.has(target)) bad.push(`${file}: make ${target}`);
    }
  }
  assert.deepEqual(bad, [], `named targets the Makefile does not define:\n  ${bad.join("\n  ")}`);
});

test("every constraint count in prose matches the build's own assertion", () => {
  const pinned = /"\$CONSTRAINTS" == "(\d+)"/.exec(read("scripts/v2/build.sh"))?.[1];
  assert.ok(pinned, "build.sh must pin a constraint count");
  const spelled = Number(pinned).toLocaleString("en-US");          // 59143 -> "59,143"
  const bad = [];
  for (const file of PROSE) {
    const text = read(file);
    // Only counts asserted as THIS circuit's size. A figure about another profile says so.
    for (const m of text.matchAll(/\b(5\d,\d{3}|6[0-5],\d{3})\b/g)) {
      if (m[1] === spelled) continue;
      const context = nearby(text, m.index);
      // The 2^16 ceiling is not a circuit size, and a figure about another profile says which.
      if (m[1] === "65,536") continue;
      if (/production|joined|base fund|at PRODUCTION|would|ceiling|busts|measured at|ptau|2\^16|spare/i.test(context)) continue;
      bad.push(`${file}: ${m[1]} (build.sh pins ${spelled})`);
    }
  }
  assert.deepEqual(bad, [], `constraint counts that disagree with build.sh:\n  ${bad.join("\n  ")}`);
});

test("a comment that says something is asserted elsewhere names a function with a real caller", () => {
  const all = sources();
  const bad = [];
  for (const file of all) {
    const text = read(file);
    for (const m of text.matchAll(/(?:asserted|checked|verified|enforced) (?:at startup )?by `(\w+)`/g)) {
      const fn = m[1];
      const callers = all.filter((f) => f !== file
        && new RegExp(`\\b${fn}\\s*\\(`).test(read(f)));
      if (callers.length === 0) {
        bad.push(`${file}: claims ${fn}() asserts something, but nothing outside a test calls it`);
      }
    }
  }
  assert.deepEqual(bad, [], `promises of a check that no production code performs:\n  ${bad.join("\n  ")}`);
});
