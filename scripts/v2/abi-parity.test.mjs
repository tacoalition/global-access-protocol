/**
 * THE HAND-WRITTEN ABIs MUST MATCH THE COMPILED CONTRACTS.
 *
 * `packages/gap-cli/src/state.ts` carries 51 ABI entries across ten contracts, written by hand. The
 * compiler never sees them and Solidity never sees the compiler's output, so the two drift silently
 * and the failure surfaces at runtime as a decode that is wrong rather than loud.
 *
 * It had already drifted. `IdentityAnchor.getCredential` returns a six-field struct; the CLI declared
 * five, omitting `metadata`: the field whitepaper Appendix III gives an anchor for the on-chain half
 * of Sybil resistance. Every field is static, so the first five decoded correctly and the sixth was
 * dropped in silence: the CLI wrote the field through `issueCredential` and could not read it back.
 * Nothing failed, which is exactly why nobody noticed.
 *
 * Comparison is by canonical signature, so a renamed parameter is allowed and a changed TYPE is not.
 * Outputs and state mutability are compared too, since neither appears in a selector and both change
 * how a call decodes.
 */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

// `state.ts` compiles to CommonJS (gap-cli is `"type": "commonjs"`), and whether a CJS named export
// is visible to a static ESM import depends on the tsx version: 4.23 hoists `abis`, 4.20 does not
// and the suite dies at parse time. Loaded dynamically and accepted from either interop shape, so
// one identical file works in both repositories.
let abis;
before(async () => {
  const mod = await import("../../packages/gap-cli/src/state.ts");
  abis = mod.abis ?? mod.default?.abis;
  assert.ok(abis, "state.ts no longer exposes `abis`: the ABI table moved or was renamed");
});

const url = (p) => new URL(`../../${p}`, import.meta.url);

// The group key in `abis` carries no contract name, so the pairing lives here. A renamed or moved
// contract fails the first assertion rather than quietly skipping its group.
const CONTRACTS = {
  did: "DIDRegistryV2",
  ita: "IdentityAnchor",
  ordb: "OnchainRiskDatabase",
  policy: "UserPolicyRegistry",
  sm: "SessionManager",
  token: "RegulatedTokenV2",
  dex: "GapCompliantDex",
  cash: "DemoCashToken",
  checker: "GapAllowlistChecker",
  venue: "RegulatedVenueV2",
};

/** Canonical ABI type, recursing into tuples so a struct's shape is compared field by field. */
const renderType = (p) =>
  p.type.startsWith("tuple")
    ? `(${(p.components ?? []).map(renderType).join(",")})${p.type.slice("tuple".length)}`
    : p.type;
const signature = (f) => `${f.name}(${(f.inputs ?? []).map(renderType).join(",")})`;
const outputs = (f) => `(${(f.outputs ?? []).map(renderType).join(",")})`;

function compiledAbi(contract) {
  const p = `contracts/out/${contract}.sol/${contract}.json`;
  assert.ok(existsSync(url(p)), `missing ${p}\n  run: make build`);
  return JSON.parse(readFileSync(url(p), "utf8")).abi.filter((x) => x.type === "function");
}

test("every group in state.ts names a contract that exists", () => {
  assert.deepEqual(Object.keys(abis).sort(), Object.keys(CONTRACTS).sort(),
    "a group was added to or removed from state.ts without updating CONTRACTS here");
});

for (const [group, contract] of Object.entries(CONTRACTS)) {
  test(`${group} matches ${contract}`, () => {
    const real = compiledAbi(contract);
    for (const entry of abis[group]) {
      const match = real.find((f) => signature(f) === signature(entry));
      assert.ok(match, `${contract}.${entry.name} is not a function on the compiled contract.`
        + `\n  state.ts declares: ${signature(entry)}`
        + `\n  the contract has:  ${real.filter((f) => f.name === entry.name).map(signature).join(" | ") || "(no function of that name)"}`);
      assert.equal(outputs(entry), outputs(match),
        `${contract}.${entry.name} returns a different shape than state.ts declares: a silent`
        + ` mis-decode, since a truncated static tuple still decodes its leading fields.`);
      assert.equal(entry.stateMutability, match.stateMutability,
        `${contract}.${entry.name} mutability drifted`);
    }
  });
}

// A count, so that deleting entries to make the suite pass is itself visible in a diff.
test("all 51 hand-written entries are covered", () => {
  const n = Object.values(abis).reduce((acc, a) => acc + a.length, 0);
  assert.equal(n, 51, `state.ts now has ${n} ABI entries; update this count deliberately`);
});
