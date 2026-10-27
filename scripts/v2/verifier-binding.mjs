#!/usr/bin/env node
//
// DOES THE CHAIN HOLD THE VERIFIER THIS BUILD PRODUCED?
//
// Everything else in this repository checks artifacts against other artifacts. This is the only
// check that asks the chain. It exists because the source-digest check said MATCH while the
// deployed verifier held the verification key of a different circuit, see deployed-bytecode.mjs.
//
//   node scripts/v2/verifier-binding.mjs <lane>          # base-fund | v2
//
// Read-only: one eth_getCode. It never signs and never broadcasts.
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  bindingVerdict, codeBytes, digestOfCode, readVerificationKey,
} from "./deployed-bytecode.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export const LANES = Object.freeze({
  "base-fund": {
    chainId: 84532,
    contract: "BaseFundLocalSessionVerifier",
    deployment: "contracts/deployments/84532-joined-base-fund.json",
    addressField: "sessionVerifier",
    artifacts: "circuits/keys/base-fund-local/artifact-manifest.json",
    verificationKey: "circuits/keys/base-fund-local/verification_key.json",
    rpc: ["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"],
  },
});

async function readJson(relative) {
  return JSON.parse(await readFile(path.join(ROOT, relative), "utf8"));
}

/** The runtime bytecode forge builds from the committed source, right now. */
export function locallyBuiltRuntimeCode(contract) {
  const hex = execFileSync("forge", ["inspect", contract, "deployedBytecode"], {
    cwd: path.join(ROOT, "contracts"), encoding: "utf8", stdio: "pipe",
  }).trim();
  return codeBytes(hex);
}

async function fetchCode(endpoints, address) {
  const failures = [];
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"],
        }),
        signal: AbortSignal.timeout(20_000),
      });
      const payload = await response.json();
      if (payload?.result) return codeBytes(payload.result);
      failures.push(`${endpoint}: ${payload?.error?.message ?? "no result"}`);
    } catch (error) {
      failures.push(`${endpoint}: ${error.message}`);
    }
  }
  // Never treated as a pass. An unreachable endpoint is an unknown, and an unknown binding is
  // exactly the state this check exists to refuse.
  throw new Error(`could not read code from any endpoint:\n  ${failures.join("\n  ")}`);
}

export async function checkVerifierBinding(laneName, { fetchCodeFor = fetchCode } = {}) {
  const lane = LANES[laneName];
  if (!lane) throw new Error(`unknown lane ${laneName}; expected one of ${Object.keys(LANES)}`);

  const [deployment, artifacts, verificationKey] = await Promise.all([
    readJson(lane.deployment), readJson(lane.artifacts),
    readVerificationKey(path.join(ROOT, lane.verificationKey)),
  ]);
  const address = deployment[lane.addressField];
  const expectedSha256 = artifacts.deployedBytecodeSha256;
  if (!/^[0-9a-f]{64}$/i.test(expectedSha256 ?? "")) {
    throw new Error(
      `${lane.artifacts} records no deployedBytecodeSha256. Without it the only binding is a ` +
        "source digest, which cannot see a verifier compiled from other settings, or one for " +
        "another circuit entirely.",
    );
  }

  const built = digestOfCode(locallyBuiltRuntimeCode(lane.contract));
  const deployed = await fetchCodeFor(lane.rpc, address);
  const verdict = bindingVerdict({ deployed, expectedSha256, verificationKey });
  return { lane: laneName, address, expectedSha256, built, verdict };
}

function report({ lane, address, expectedSha256, built, verdict }) {
  const line = "─".repeat(88);
  console.log(line);
  console.log(`lane ${lane}   verifier ${address}`);
  console.log(`  manifest deployedBytecodeSha256  ${expectedSha256}`);
  console.log(`  forge build of committed source  ${built}${built === expectedSha256 ? "  (agrees)" : "  ← DISAGREES with the manifest"}`);
  console.log(`  eth_getCode                      ${verdict.sha256 ?? "(no code)"}`);
  console.log(line);
  if (verdict.ok) {
    console.log("✅ the chain holds the verifier this build produced.");
    return 0;
  }
  console.error(`❌ ${verdict.detail}`);
  console.error(
    "\nThe deployed verifier is not this build. Proofs from the committed artifacts will be\n" +
    'rejected by SessionManager ("SM: invalid proof").\n\n' +
    "THIS IS A WHOLE-LANE REDEPLOY, not a verifier swap. `SessionManager.verifier` is immutable,\n" +
    "and so is `sessionManager` on TransactionFilterV2, RegulatedVenueV2 and the allowlist\n" +
    "adapter: there is no setter anywhere in the chain. A new verifier therefore needs a new\n" +
    "SessionManager, which needs new filters, venue and adapter, which is what\n" +
    "DeployJoinedBaseFundLocal.s.sol already does end to end.\n\n" +
    "Or check out the commit the deployment was made from: the verifier on chain is byte-\n" +
    "identical to the build at fa068c6^, the commit before the spending leaf was blinded.",
  );
  return 1;
}

const invokedAsScript =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
  checkVerifierBinding(process.argv[2] ?? "base-fund")
    .then((result) => { process.exitCode = report(result); })
    .catch((error) => { console.error(error.message); process.exitCode = 1; });
}
