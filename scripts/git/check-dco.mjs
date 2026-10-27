#!/usr/bin/env node
// Developer Certificate of Origin, checked, for a commit message and for every commit in a PR.
//
// Each commit must carry a `Signed-off-by: Name <email>` trailer whose email is the commit
// author's. That line is the contributor certifying the DCO (https://developercertificate.org/),
// and `git commit -s` writes it. Matching on the AUTHOR, not the committer, is what makes it mean
// something: the sign-off is a statement by the person who wrote the change.
//
// Usage:
//   node scripts/git/check-dco.mjs <path-to-message-file>   # commit-msg hook
//   node scripts/git/check-dco.mjs --range <base>..<head>   # every commit in a PR, for CI
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const SIGNOFF = /^Signed-off-by: .+ <([^<>\s]+)>\s*$/gm;
const signoffEmails = (message) => [...message.matchAll(SIGNOFF)].map((m) => m[1].toLowerCase());

const hint = [
  "    Every commit needs a DCO sign-off: `git commit -s` adds it.",
  "    To fix the commits already on a branch:  git rebase --signoff <base>  then force-push.",
  "    See CONTRIBUTING.md, \"Licensing and sign-off\".",
].join("\n");

const argv = process.argv.slice(2);
const rangeFlag = argv.indexOf("--range");

if (rangeFlag === -1) {
  // Hook mode. The author is whoever git is about to record, so compare against that identity.
  const message = readFileSync(argv[0], "utf8");
  const subject = message.split("\n")[0] ?? "";
  if (/^(Merge|fixup!|squash!)\s/.test(subject)) process.exit(0);
  const author = execFileSync("git", ["var", "GIT_AUTHOR_IDENT"], { encoding: "utf8" });
  const email = (author.match(/<([^>]*)>/)?.[1] ?? "").toLowerCase();
  if (!signoffEmails(message).includes(email)) {
    console.error(`\n  ✗ no Signed-off-by for the author <${email}>\n\n${hint}\n`);
    process.exit(1);
  }
  process.exit(0);
}

const range = argv[rangeFlag + 1] ?? "";
if (!/^[0-9a-f]{7,64}\.\.[0-9a-f]{7,64}$/.test(range)) {
  console.error(`  ✗ --range must be <sha>..<sha>, got: ${range}`);
  process.exit(2);
}
const log = execFileSync(
  "git", ["log", "--no-merges", "--format=%H%x00%ae%x00%B%x1e", range],
  { encoding: "utf8" },
);
const failures = log
  .split("\x1e")
  .map((record) => record.replace(/^\n/, ""))
  .filter(Boolean)
  .map((record) => {
    const [sha, email, message] = record.split("\x00");
    return { sha, email: email.toLowerCase(), message };
  })
  .filter(({ email, message }) => !signoffEmails(message).includes(email));

if (failures.length > 0) {
  console.error(`\n  ✗ ${failures.length} commit(s) without a sign-off by their author:\n`);
  for (const { sha, email, message } of failures) {
    console.error(`    ${sha.slice(0, 12)}  <${email}>  ${message.split("\n")[0]}`);
  }
  console.error(`\n${hint}\n`);
  process.exit(1);
}
console.log(`  ✓ every commit in ${range} is signed off by its author`);
