import assert from "node:assert/strict";
import test from "node:test";
import { monitorKeyFor, rememberMonitorKey, assertDemoKeypairAgrees } from "../src/monitor-key";

/**
 * THE DRIFT THIS PREVENTS WAS SILENT AND TOTAL. The prover used to seal to a compile-time constant
 * while the CLI read only the `keyId` from the chain and discarded the point. After a
 * `rotateMonitorKey` the grant still succeeded, `pub[18]` carries the new id and the SessionManager
 * accepts it, but the envelope was sealed to the OLD point, so the monitor could never decrypt and
 * no session was ever attestable. Nothing failed; sessions simply stopped working.
 */
test("a prover refuses to seal to a key the chain has not declared", () => {
  rememberMonitorKey(7n, 111n, 222n);
  assert.deepEqual(monitorKeyFor(7n), { x: 111n, y: 222n }, "a recorded key resolves");
  assert.throws(
    () => monitorKeyFor(9n),
    /no monitor key recorded/,
    "an unrecorded key must REFUSE: falling back to a constant is what produced an envelope that "
      + "passed every on-chain check and no monitor could open",
  );
});

/** The comment on these constants used to claim this check happened. Now it does. */
test("the demo scalar really derives the demo point", async () => {
  await assertDemoKeypairAgrees();
});
