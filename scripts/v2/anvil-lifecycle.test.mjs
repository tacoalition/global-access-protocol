import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { afterEach, test } from "node:test";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "../..");
const stopScript = join(root, "scripts/v2/anvil-stop.sh");
const children = new Set();

afterEach(async () => {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    if (child.exitCode === null && child.signalCode === null) await once(child, "exit");
  }
  children.clear();
});

function processLine(pid, field) {
  return execFileSync("ps", ["-ww", "-p", String(pid), "-o", `${field}=`], {
    encoding: "utf8",
  }).replace(/\n+$/, "");
}

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "gap-v2-anvil-test-"));
  const executable = join(directory, "anvil-owned-fixture");
  const pidFile = join(directory, "anvil.pid");
  await symlink("/bin/sleep", executable);
  const child = spawn(executable, ["30"], { stdio: "ignore" });
  children.add(child);
  await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  assert.equal(child.exitCode, null);
  return { child, pidFile };
}

async function record(child, pidFile, command = processLine(child.pid, "command")) {
  const start = processLine(child.pid, "lstart");
  await writeFile(pidFile, `${child.pid}\n${start}\n${command}\n`, { mode: 0o600 });
}

function stop(pidFile) {
  return execFileSync("bash", [stopScript], {
    cwd: root,
    env: { ...process.env, GAP_ANVIL_PID_FILE: pidFile },
    encoding: "utf8",
  });
}

test("stops the exact PID and process signature recorded by the launcher", async () => {
  const { child, pidFile } = await fixture();
  await record(child, pidFile);
  assert.match(stop(pidFile), /stopped GAP v2-owned anvil/);
  await once(child, "exit");
  children.delete(child);
  assert.notEqual(child.signalCode, null);
});

test("refuses a reused or unrelated PID without terminating it", async () => {
  const { child, pidFile } = await fixture();
  await record(child, pidFile, "anvil-but-not-the-recorded-command");
  assert.throws(() => stop(pidFile), /not the GAP v2-owned Anvil process/);
  assert.equal(child.exitCode, null);
  assert.equal(child.signalCode, null);
});
