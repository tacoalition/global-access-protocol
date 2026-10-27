#!/usr/bin/env tsx
// Parity de-risk for browser witness-building (#21): the holder-mirror path (server) and the
// on-chain-views path (browser) must produce the BYTE-IDENTICAL witness input. Run against a
// chain where the demo user is onboarded (make up + `sidecar onboard user`).
import { contracts, initIdentities, USER } from "./state";
import { prepareSession } from "./cli";
import { buildSessionInputFromWitness } from "./prover";
import { fetchWitness } from "./witness";

(async () => {
  await initIdentities();
  const { d } = contracts();
  const prep = await prepareSession(USER, d.policyId, "transfer"); // holder-mirror input (token default clauses)
  const w = await fetchWitness(USER, d.policyId, prep.validUntil,
    { gatedContract: d.regulatedToken, ordbAddress: d.ordb, clauses: tokenClauses() });
  const wi = await buildSessionInputFromWitness(w);

  const a = JSON.stringify(prep.input);
  const b = JSON.stringify(wi.input);
  if (a === b) {
    console.log("PARITY OK, holder-mirror input === on-chain-views input");
    process.exit(0);
  }
  // report the first differing key
  const ka = prep.input as Record<string, unknown>, kb = wi.input as Record<string, unknown>;
  for (const k of Object.keys(ka)) {
    if (JSON.stringify(ka[k]) !== JSON.stringify(kb[k])) {
      console.log(`MISMATCH at '${k}':\n  mirror: ${JSON.stringify(ka[k])}\n  views:  ${JSON.stringify(kb[k])}`);
    }
  }
  process.exit(1);
})();

function tokenClauses() {
  return [
    { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n },
    { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },
    { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  ];
}
