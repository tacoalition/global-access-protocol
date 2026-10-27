#!/usr/bin/env tsx
// #22: proves the grant queue prevents the same-account nonce race. Fires TWO venue sessions for
// the SAME user (General + Reg-D transfer, different policies) CONCURRENTLY. Both must succeed, 
// without serialization the second would revert ("SM: nonce binding"). Run on a fresh chain.
import { contracts, initIdentities, USER } from "./state";
import { venueSession } from "./venue";
import { cmdOnboard } from "./cli";

(async () => {
  await initIdentities();
  const { d, did, sm } = contracts();
  const { toHex32 } = await import("./state");
  if (!(await did.read.isRegistered([toHex32(USER.did)]))) await cmdOnboard(USER, "•");

  // fire concurrently, same account, different zone policies
  const results = await Promise.allSettled([
    venueSession(USER, "general", "transfer"),
    venueSession(USER, "reg-d", "transfer"),
  ]);
  const failed = results.filter((r) => r.status === "rejected");

  const genOk = await sm.read.hasValidSession([USER.address, (d as any).genTransferPolicy, d.venue as `0x${string}`]);
  const regdOk = await sm.read.hasValidSession([USER.address, (d as any).regdTransferPolicy, d.venue as `0x${string}`]);
  console.log(`concurrent grants, rejected: ${failed.length}, general active: ${genOk}, reg-d active: ${regdOk}`);
  if (failed.length === 0 && genOk && regdOk) {
    console.log("QUEUE OK: both same-account grants succeeded concurrently (no nonce race)");
    process.exit(0);
  }
  for (const f of failed) if (f.status === "rejected") console.log("  reject:", String(f.reason).split("\n")[0]);
  process.exit(1);
})();
