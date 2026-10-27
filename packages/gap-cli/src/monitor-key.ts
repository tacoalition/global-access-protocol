// THE DEMO'S TRANSACTION-MONITOR KEYPAIR, published on purpose.
//
// In the same spirit as Anvil's test accounts: this scalar protects nothing, it is in version
// control, and anyone can read a `make demo` session with it. That is the point: it is what lets the
// reference run the REAL authenticated cipher instead of a cleartext stand-in.
//
// WHAT THIS REPLACES. The local deployment used to publish a placeholder monitor key, literally the
// point (1, 2), which is not on the curve and cannot be an ECDH target, so there was nothing to
// encrypt to, and `SessionGranted` carried four raw field elements. A review pulled two wallets'
// pseudonyms off the chain with no keys and showed they were identical: "one person, many wallets"
// rendered publicly linkable, against the white paper's §5.2 property 5, while the disclosure panel
// claimed the envelope "opens only to the monitor key".
//
// A real key with a published scalar is honest in a way a fake key with a true-sounding claim is not:
// the mechanism is now the production one, and what is weak about the demo is the SECRET, which is
// stated here rather than implied anywhere.
export const DEMO_MONITOR_SCALAR =
  0x5ca1ab1e0000000000000000000000000000000000000000000000000000001n;

// Derived from the scalar above via `babyJubPublicKeyFromScalar`. `assertDemoKeypairAgrees()` below
// checks that claim rather than asserting it in prose: an earlier version of this comment said the
// check happened "at startup" when its only caller was a test.
export const DEMO_MONITOR_PUBLIC_KEY = {
  x: 16748179299083121587732023489771520327604751973068439960861183512353334892500n,
  y: 19635820508302344050006821993285090849409310344111641696431076536461503592449n,
} as const;

import { babyJubPublicKeyFromScalar, monitorScalarMatchesKey } from "@tac-gap/sdk";

/**
 * The published point a session must be sealed to, keyed by the `monitorKeyId` the ORDB declares.
 *
 * WHY A LOOKUP RATHER THAN A CONSTANT. The prover used to encrypt to `DEMO_MONITOR_PUBLIC_KEY` while
 * the CLI read only the `keyId` from the chain and threw the point away. After a `rotateMonitorKey`
 * the grant would still succeed, `pub[18]` carries the NEW id and the SessionManager accepts it, 
 * but the envelope was sealed to the OLD point, so the monitor could never decrypt and no session
 * was ever attestable. Silent, and exactly the drift the comment claimed was caught.
 */
const published = new Map<string, { x: bigint; y: bigint }>();

/** Record what the chain declares. Called wherever the ORDB's monitor key is read. */
export function rememberMonitorKey(keyId: bigint, x: bigint, y: bigint): void {
  published.set(keyId.toString(), { x, y });
}

/**
 * The point for this key id, or a refusal. A prover that cannot name the key the chain declares must
 * STOP rather than fall back to a compile-time constant: falling back is what produced an
 * undecryptable envelope that still passed every on-chain check.
 */
export function monitorKeyFor(keyId: bigint): { x: bigint; y: bigint } {
  const hit = published.get(keyId.toString());
  if (!hit) {
    throw new Error(
      `GAP CLI: no monitor key recorded for keyId ${keyId}. The ORDB publishes one and the prover `
      + "must seal to it; sealing to a stale key yields a session no monitor can ever attest.",
    );
  }
  return hit;
}

/** The demo scalar really does derive the demo point. Asserted, where the comment used to claim it. */
export async function assertDemoKeypairAgrees(): Promise<void> {
  const ok = await monitorScalarMatchesKey(DEMO_MONITOR_SCALAR, DEMO_MONITOR_PUBLIC_KEY);
  if (!ok) {
    throw new Error("GAP CLI: DEMO_MONITOR_PUBLIC_KEY is not the point DEMO_MONITOR_SCALAR derives");
  }
  await babyJubPublicKeyFromScalar(DEMO_MONITOR_SCALAR);
}
