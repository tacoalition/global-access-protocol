#!/usr/bin/env node
// Conventional Commits, checked, for commit messages and for PR titles.
//
// DELIBERATELY PERMISSIVE. A linter that rejects a good message on a technicality costs more than it
// saves, and people route around it. This enforces the SHAPE (so history stays machine-readable and
// greppable) and otherwise gets out of the way. It does not police wording, length of the body, or
// capitalisation of the subject.
//
// Usage:
//   node scripts/git/check-commit-message.mjs <path-to-message-file>   # commit-msg hook
//   node scripts/git/check-commit-message.mjs --title "feat(cli): ..."  # a PR title, for CI
import { readFileSync } from "node:fs";

// The types this repository actually has a use for. `chore` is last on purpose: it is the one that
// becomes a dumping ground, and most "chore" commits are really build, ci, refactor or docs.
const TYPES = [
  "feat",     // a capability that was not there before
  "fix",      // a defect, including a wrong or misleading document
  "docs",     // documentation only, no behaviour change
  "test",     // tests only
  "refactor", // behaviour-preserving restructuring
  "perf",     // measurably faster or cheaper, including constraint count
  "build",    // the build, the circuit toolchain, dependencies
  "ci",       // workflows and the checks they run
  "revert",
  "chore",
];

const argv = process.argv.slice(2);
const titleFlag = argv.indexOf("--title");
const subject = titleFlag !== -1
  ? (argv[titleFlag + 1] ?? "")
  : (readFileSync(argv[0], "utf8").split("\n")[0] ?? "");

// Merge and fixup commits are git's, not ours.
if (/^(Merge|Revert|fixup!|squash!)\s/.test(subject)) process.exit(0);

const fail = (why, hint) => {
  console.error(`\n  ✗ ${why}\n`);
  console.error(`    subject: ${subject}\n`);
  if (hint) console.error(`${hint}\n`);
  console.error("    Conventional Commits:  type(optional scope)!: subject");
  console.error(`    types: ${TYPES.join(", ")}`);
  console.error("    ! or a BREAKING CHANGE: footer marks a break, see CONTRIBUTING.md for what");
  console.error("    counts as breaking here (it is not the same as a Solidity ABI change).\n");
  process.exit(1);
};

const m = subject.match(/^([a-z]+)(?:\(([^)]+)\))?(!)?: (.+)$/);
if (!m) {
  fail(
    "the subject is not a Conventional Commit",
    "    e.g.  fix(contracts): bind revocation grounds to the session they close",
  );
}
const [, type, scope, bang, text] = m;

if (!TYPES.includes(type)) fail(`"${type}" is not one of this repository's types`);
if (scope !== undefined && scope.trim() === "") fail("an empty scope, write `type: subject` instead");
if (text.trim().length < 10) fail("the subject says too little to be useful on its own");
if (text.endsWith(".")) fail("no full stop at the end of the subject");

// A warning, not a failure: a long subject is a style issue, and failing on it would be the kind of
// technicality that teaches people to pass `--no-verify`.
if (subject.length > 72) {
  console.error(`  ⚠ subject is ${subject.length} chars; under 72 reads better in logs. Not blocking.`);
}
if (bang) {
  console.error("  ⚠ marked BREAKING. Make sure the body says what breaks and what a consumer must do.");
}
process.exit(0);
