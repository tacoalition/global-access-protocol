#!/usr/bin/env tsx
// GAP v2 CLI, spin up nothing, just interact. Drives the two-party compliance story:
// sender onboard → sender session → transfer blocked (no receiving session, GAP-H6) →
// recipient onboard + receiving session → transfer succeeds → TM flag → new session rejected.
// Everything privacy-touching (DID/credentials/proof) is computed here from each party's secret
// identity; the chain holds only commitments.
import { DEMO_MONITOR_SCALAR, rememberMonitorKey } from "./monitor-key";
import { Command } from "commander";
import {
  accountsOf, contracts, ordbAt, initIdentities, wallet, abis, USER, RECEIVER, DemoIdentity,
  DEPLOYER_PK, toHex32, publicClient, CHAIN_ID, walletOf,
} from "./state";
import { walletSetRoot, walletSetWitness } from "./wallet-set";
import { buildSessionInput, proveInputServer, credentialCommitment, pseudonymFor, Holder, SessionScenario } from "./prover";
import { GrantQueue, inspectNamedSession, reviewStoredSession } from "@tac-gap/sdk";
// The credential-mint path lives in ./onboard: it is the only place in this lane
// that writes a credential, and every write there is gated. Re-exported here so
// sidecar.ts / queue-test.ts / witness.ts keep their existing import surface.
import { ATTRS, CLAUSES, cmdOnboard, regimeAttrs } from "./onboard";
import { bold, dim, green, red } from "./ui";
import { txWait } from "./tx";

export { holdersOnChain, ATTRS, cmdOnboard };

const A = (x: string): bigint => BigInt(x);

// Every onboarded identity, with its leaf-folded expiries read back from the anchor: the
// offchain trees must mirror ALL of them or the recomputed roots won't match the chain.
async function holdersOnChain(): Promise<Holder[]> {
  const { d, did, ita } = contracts();
  const holders: Holder[] = [];
  for (const id of [USER, RECEIVER]) {
    if (!(await did.read.isRegistered([toHex32(id.did)]))) continue;
    const c0 = (await ita.read.getCredential([d.idRegime as `0x${string}`, toHex32(id.did)])) as any;
    const c1 = (await ita.read.getCredential([d.invRegime as `0x${string}`, toHex32(id.did)])) as any;
    const leafOf = (c: any): bigint => (c.issuedAt === 0n || c.revoked ? 0n : A(c.commitment));
    holders.push({
      did: id.did, privateSalt: id.privateSalt, account: A(id.address),
      credExpiresAt: [c0.expiresAt, c1.expiresAt],
      credLeaves: [leafOf(c0), leafOf(c1)],
      // A PERSON-level root over the whole wallet set: the DID leaf is the same
      // whichever of this person's wallets is transacting, which is exactly why a
      // second wallet does not need a second DID.
      spendingKeyRoot: await walletSetRoot(accountsOf(id), id.privateSalt),
      spendingKeyWitness: await walletSetWitness(accountsOf(id), id.address, id.privateSalt),
    });
  }
  return holders;
}

async function cmdStatus() {
  const { d, did, ordb, sm, token } = contracts();
  console.log(bold("\nGAP v2, deployment"));
  for (const k of ["sessionManager", "identityAnchor", "classificationAnchor", "regulatedToken", "ordb", "userPolicyRegistry"]) {
    console.log(`  ${k.padEnd(22)} ${d[k]}`);
  }
  const sym = await token.read.symbol();
  for (const id of [USER, RECEIVER]) {
    const registered = await did.read.isRegistered([toHex32(id.did)]);
    const bal = await token.read.balanceOf([id.address]);
    const policy = id === USER ? d.policyId : d.receivingPolicyId;
    const valid = await sm.read.hasValidSession([id.address, policy as `0x${string}`, d.regulatedToken as `0x${string}`]);
    const ps = await pseudonymFor(A(d.idRegime), A(d.regulatedToken), id);
    const flagged = await ordb.read.isFlagged([toHex32(ps)]);
    console.log(bold(`\n${id.label}`));
    console.log(`  DID registered:  ${registered ? green("yes") : "no"}`);
    console.log(`  ${sym} balance:      ${bal / 10n ** 18n}`);
    console.log(`  active session:  ${valid ? green("yes") : "no"} ${dim(id === USER ? "(transfer policy)" : "(receiving policy)")}`);
    console.log(`  pseudonym flagged: ${flagged ? red("yes") : green("no")}`);
  }
  console.log();
}

/** The gating target a session is scoped to, the legacy token (default) or the venue. */
export interface SessionTarget {
  gatedContract: string;   // pseudonym scope + pub[15]
  ordbAddress: string;     // the risk DB whose TM attests
  clauses: typeof CLAUSES; // the zone/policy DNF clause template (must match on-chain clausesHash)
}

/** Build the witness input + do all pre-proof checks WITHOUT proving (browser-proving split, #17). */
export async function prepareSession(id: DemoIdentity, policyId: string, kind: string, target?: SessionTarget) {
  const { d, did, ita, sm, policy } = contracts();
  const tgt: SessionTarget = target ?? { gatedContract: d.regulatedToken, ordbAddress: d.ordb, clauses: CLAUSES };
  const ordb = ordbAt(tgt.ordbAddress);

  // read live roots + nonce the proof must bind to
  const [mkX, mkY, keyId] = await ordb.read.getMonitorKey();
  // Record the POINT, not just the id. The prover seals to whatever the chain declares; discarding
  // the point here is what let a rotated key produce envelopes no monitor could open.
  rememberMonitorKey(BigInt(keyId as string | bigint), BigInt(mkX as string | bigint), BigInt(mkY as string | bigint));
  const nonce = await sm.read.sessionNonce([id.address]);
  const version = await policy.read.latestVersion([policyId as `0x${string}`]);
  // chain time, not wall clock: the SM checks validUntil against block.timestamp + policy cap
  const validUntil = (await publicClient().getBlock()).timestamp + 1800n;

  // ORDB full-key non-membership witness, from the LIVE risk tree (GAP-H1). For a flagged
  // pseudonym no bracketing low leaf exists: no witness, no proof. One view call returns the
  // witness AND the root it is valid for (same block → no fetch race).
  const ps = await pseudonymFor(A(d.idRegime), A(tgt.gatedContract), id);
  if (await ordb.read.isFlagged([toHex32(ps)])) {
    throw new Error("pseudonym is flagged in the ORDB, cannot prove non-membership");
  }
  const [lowIndex, lowKey, nextKey, siblings, riskRoot] =
    await ordb.read.getNonMembershipWitness([toHex32(ps)]);
  const rdb: SessionScenario["rdb"] = {
    root: A(riskRoot as string),
    index: Number(lowIndex), lowKey: A(lowKey as string), nextKey: A(nextKey as string),
    siblings: (siblings as readonly string[]).map((s) => A(s)),
  };

  // all onboarded holders (tree mirror) + this party's own holder record, with PREFLIGHT:
  // recompute each of the prover's leaves vs the stored commitment before paying for a proof.
  const allHolders = await holdersOnChain();
  const person = allHolders.find((h) => h.did === id.did);
  if (!person) throw new Error(`${id.label} is not onboarded, run onboarding first`);
  // Re-point the person's record at the wallet actually transacting. The DID leaf is
  // untouched (it folds the person-level wallet-set root, not the account), so the
  // mirror stays correct; only `account` and its membership proof change. A wallet
  // outside the set has no proof here and never reaches the prover.
  const holder = {
    ...person,
    account: A(id.address),
    spendingKeyWitness: await walletSetWitness(accountsOf(id), id.address, id.privateSalt),
  };
  const mirror = allHolders.map((h) => (h.did === id.did ? holder : h));
  const preflight = [
    { regime: d.idRegime, attrs: regimeAttrs(ATTRS, 0), exp: holder.credExpiresAt[0], name: "identity" },
    { regime: d.invRegime, attrs: regimeAttrs(ATTRS, 1), exp: holder.credExpiresAt[1], name: "investor" },
  ];
  for (const p of preflight) {
    const stored = (await ita.read.getCredential([p.regime as `0x${string}`, toHex32(id.did)])) as any;
    if (stored.issuedAt === 0n) throw new Error(`no ${p.name} credential, onboard first`);
    if (stored.revoked) throw new Error(`${p.name} credential is revoked`);
    const leaf = await credentialCommitment(A(d.identityAnchor), A(p.regime), A(d.ikId), p.attrs, p.exp, id);
    if (toHex32(leaf) !== stored.commitment) {
      throw new Error(`${p.name} credential commitment mismatch, stored record diverges from the leaf`);
    }
  }

  const scenario: SessionScenario = {
    holder, allHolders: mirror,
    chainId: BigInt(CHAIN_ID), sessionManager: A(d.sessionManager), policyId: A(policyId),
    policyVersion: BigInt(version), validUntil, accountNonce: nonce,
    ita0: A(d.identityAnchor), ita1: A(d.identityAnchor),
    regime0: A(d.idRegime), regime1: A(d.invRegime),
    ikId0: A(d.ikId), ikId1: A(d.ikId), gatedContract: A(tgt.gatedContract), ordbId: A(tgt.ordbAddress),
    monitorKeyId: A(keyId as string), attrs: ATTRS, clauses: tgt.clauses, rdb,
  };
  const { input, ciphertext, roots } = await buildSessionInput(scenario);

  // sanity: every offchain-recomputed root must equal the chain's (Poseidon parity)
  const chainCredRoot = await ita.read.getAttributeRegimeRoot([d.idRegime as `0x${string}`]);
  const chainCredRoot1 = await ita.read.getAttributeRegimeRoot([d.invRegime as `0x${string}`]);
  const chainDidRoot = await did.read.root();
  if (A(chainCredRoot as string) !== roots.credRoot0 || A(chainCredRoot1 as string) !== roots.credRoot1) {
    throw new Error("root mismatch, offchain != on-chain credential root");
  }
  if (A(chainDidRoot as string) !== roots.didRoot) {
    throw new Error("root mismatch, offchain != on-chain DID root");
  }
  const liveRiskRoot = await ordb.read.root();
  if (A(liveRiskRoot as string) !== roots.riskRoot) {
    throw new Error("risk root moved while proving, retry the session");
  }
  console.log(dim(`   ✓ offchain roots == on-chain roots (DID, cred×2, risk)  ${(chainCredRoot as string).slice(0, 14)}…`));
  return { input, ciphertext, validUntil, version: Number(version), policyId };
}

/** Submit a proof (server- or browser-generated) → grantSession + TM attest. */
export async function submitSession(
  id: DemoIdentity, policyId: string, validUntil: bigint, version: number,
  pA: unknown, pB: unknown, pC: unknown, pub: unknown, ciphertext: string,
  opts: { monitorAttests?: boolean } = {},
) {
  const { d } = contracts();
  const party = wallet(id.pk);
  try {
    const h = await party.writeContract({ address: d.sessionManager as `0x${string}`, abi: abis.sm, functionName: "grantSession",
      args: [policyId as `0x${string}`, version, validUntil, pA as any, pB as any, pC as any, pub as any, ciphertext as `0x${string}`] });
    const r = await txWait(h);
    console.log(green(`   ✓ session granted on-chain  `) + dim(`(gas ${r.gasUsed}), pending TM attestation`));
  } catch (e: any) {
    const reason = (e.shortMessage || e.metaMessages?.[0] || e.message || "").split("\n")[0];
    throw new Error("session rejected on-chain, " + reason);
  }

  // TWO PARTIES, AND THE SECOND ONE IS NOT THIS WALLET. The grant above is everything the holder
  // can do; the session is installed UNATTESTED and unusable until the ORDB's Transaction Monitor
  // independently agrees (GAP-H3). Calling straight through keeps the demo a single command, but
  // the monitor's work is a separate function with a separate key that shares NOTHING with the call
  // above, not the proof, not the public signals, not the ciphertext.
  //
  // `monitorAttests: false` stops here, which is the only way to SEE that: a granted, unattested
  // session that the Transaction Filter still refuses.
  if (opts.monitorAttests === false) {
    console.log(dim("   stopping before attestation: the session exists and is NOT yet usable"));
    console.log(dim("   run `make cli ARGS=attest` to have the Transaction Monitor review it\n"));
    return;
  }
  await attestSessionAsMonitor(id, policyId);
}

/**
 * The Transaction Monitor's half of a grant: open the envelope, confirm it reopens what was
 * proven, attest. A different party, a different key, and deliberately NO access to the submitter's
 * proof: every input is read back off the chain.
 *
 * That last part is the change. This used to live inside `submitSession` and built the AEAD context
 * out of the `pub` array the submitter handed in. A monitor authenticating against the submitter's
 * own numbers is authenticating against nothing; it only held up because the opened plaintext was
 * then checked against the contract-written envelope. The decision itself is now
 * `@tac-gap/sdk reviewStoredSession`, which takes the stored session and nothing else.
 */
export async function attestSessionAsMonitor(
  id: DemoIdentity, policyId: string,
) {
  const { d, sm } = contracts();
  const pid = policyId as `0x${string}`;

  // WHICH session, though. If the account already held a live attested unexpired session, the grant
  // was STAGED (SessionManager._install) and `sessionDigestOf` names the STAGE. Opening the LIVE
  // slot's ciphertext and then attesting that digest would promote, and so make spendable: a
  // session whose ciphertext this monitor never checked. Both slots and the named digest are read
  // together and resolved by the one shared mirror of the contract's own selection rule, so the
  // ciphertext opened below and the digest attested at the end are the same session by construction.
  const [liveSlot, pendingSlot, namedDigest, chainNow, sessionNonce] = await Promise.all([
    sm.read.getSession([id.address, pid]),
    sm.read.getPendingSession([id.address, pid]),
    sm.read.sessionDigestOf([id.address, pid]),
    publicClient().getBlock().then((b) => b.timestamp),
    sm.read.sessionNonce([id.address]),
  ]);
  const target = inspectNamedSession(
    id.address,
    { live: liveSlot as any, pending: pendingSlot as any, named: namedDigest as `0x${string}` },
    { nowSeconds: chainNow },
  );
  if (!target.present || target.expired) {
    throw new Error("no unexpired session to attest, re-grant the session");
  }
  if (target.attested) {
    // A stage is installed unattested by construction, so this can only be the live slot: there
    // is genuinely nothing new to attest.
    throw new Error("the session the contract names is already attested");
  }
  if (!target.digestMatchesNamed) {
    throw new Error("session slots moved while attesting, retry the session");
  }

  // A REAL DECRYPT, not an abi-decode. The envelope used to travel in the clear, because the local
  // deployment published a placeholder monitor key and so had nothing to encrypt to, a reviewer
  // read two wallets' pseudonyms off the chain and showed they matched, which makes "one person,
  // many wallets" publicly linkable. The demo monitor's scalar is published in `monitor-key.ts` and
  // protects nothing; what matters is that the MECHANISM is the production one.
  //
  // Poseidon is injected because the SDK is config-injected by design and must not reach into
  // `circuits/`. A mismatched hash fails the reopen check rather than passing, since the committed
  // values are read from the chain.
  // The LIVE monitor key, read from THE SESSION'S OWN ORDB, not the default one, because the
  // venue and pool acts run a second ORDB with its own monitor key. A session proven against a key
  // that has since rotated still opens (the AEAD key is derived from the id inside the envelope,
  // so a monitor holding the old scalar sees nothing wrong); comparing against the live id is the
  // only thing that refuses it.
  const [, , liveMonitorKeyId] = (await ordbAt(target.session.ordb).read.getMonitorKey()) as
    [bigint, bigint, `0x${string}`];

  const gc = require("../../../circuits/scripts/v2/gap_crypto.js");
  const reviewed = await reviewStoredSession({
    chainId: CHAIN_ID,
    sessionManager: d.sessionManager as `0x${string}`,
    account: id.address,
    sessionNonce: sessionNonce as bigint,
    session: target.session,
    monitorScalar: DEMO_MONITOR_SCALAR,
    expectedMonitorKeyId: BigInt(liveMonitorKeyId),
    hash: { h2: gc.h2, h3: gc.h3 },
  });

  // Bind the write to the digest of the session just opened, NOT a fresh `sessionDigestOf` read,
  // which is what would promote a session installed since. Equal to `namedDigest` by the check
  // above, so a stage is still promoted atomically.
  const tm = wallet(DEPLOYER_PK); // the ORDB's TM is the deployer in this demo
  const ha = await tm.writeContract({ address: d.sessionManager as `0x${string}`, abi: abis.sm, functionName: "attestSession",
    args: [id.address, policyId as `0x${string}`, target.digest] });
  await txWait(ha);
  // The opened pseudonym is deliberately NOT logged, printing it here would undo the encryption
  // for anyone reading the demo output. The grant nonce it authenticated under is safe and shows
  // the monitor really opened something.
  console.log(green("   ✓ TM decrypted + reopened the commitments, session attested (GAP-H3)")
    + dim(`  (grant nonce ${reviewed.accountNonce})`));
  // Read off the session, not taken as an argument: the expiry is the contract's, and a monitor
  // that reported the submitter's number would be reporting a claim rather than a fact.
  const expiry = Number(target.session.validUntil);
  console.log(dim(`   valid until ${new Date(expiry * 1000).toLocaleTimeString()}: the TF now checks a single expiry\n`));
}

// Serialize prepare→prove→submit per account: the proof binds the account nonce, so concurrent
// same-account grants would race (the second reverts on a stale nonce). Different accounts run in
// parallel. (SDK GrantQueue.)
const grantQueue = new GrantQueue();

/** Full server-side session: prepare (build+check the input) → prove locally → submit. */
export async function cmdSession(
  id: DemoIdentity, policyId: string, step: string, kind: string, target?: SessionTarget,
  opts: { monitorAttests?: boolean } = {},
) {
  return grantQueue.enqueue(id.address, async () => {
    console.log(bold(`\n${step}. Open a ${kind} for the ${id.label}`) + dim("  (ZK proof against LIVE on-chain roots)"));
    const prep = await prepareSession(id, policyId, kind, target);
    process.stdout.write(dim("   generating Groth16 proof… "));
    const { pA, pB, pC, pub, provingMs } = await proveInputServer(prep.input);
    console.log(green(`done (${provingMs} ms)`));
    await submitSession(
      id, policyId, prep.validUntil, prep.version, pA, pB, pC, pub, prep.ciphertext, opts,
    );
  });
}

export async function cmdTransfer(amount: string, step: string, expectBlocked = false) {
  const { d, token } = contracts();
  const user = wallet(USER.pk);
  const amt = BigInt(amount) * 10n ** 18n;
  // Read the ticker off the deployed token: never hardcode a symbol into an operator surface.
  const sym = await token.read.symbol();
  console.log(bold(`\n${step}. Transfer ${amount} ${sym} → ${RECEIVER.label}`) + dim("  (TF gates BOTH sides, GAP-H6)"));
  try {
    const h = await user.writeContract({ address: d.regulatedToken as `0x${string}`, abi: abis.token, functionName: "transfer", args: [RECEIVER.address, amt] });
    const r = await txWait(h);
    const bal = await token.read.balanceOf([USER.address]);
    if (expectBlocked) {
      console.log(red("   ✗ unexpected: transfer passed without a receiving session"));
      throw new Error("recipient gate did not fire");
    }
    console.log(green(`   ✓ transfer succeeded  `) + dim(`(gas ${r.gasUsed}), sender balance now ${bal / 10n ** 18n} ${sym}\n`));
  } catch (e: any) {
    const reason = String(e.shortMessage || e.message || "");
    if (expectBlocked) {
      // the block must come from the RECIPIENT gate specifically (audit: don't let a broken
      // sender path or balance failure masquerade as a passing negative test)
      if (!reason.includes("recipient not compliant")) {
        throw new Error("transfer blocked for the WRONG reason: " + oneLine(reason));
      }
      console.log(green("   ✓ transfer correctly blocked: ") + dim("recipient not compliant (no receiving session)\n"));
      return;
    }
    throw new Error("transfer reverted: " + oneLine(reason));
  }
}

/** viem puts the revert reason on the line AFTER "reverted with the following reason:", so taking
 *  only the first line printed the preamble and dropped the reason. Keep every line, joined. */
function oneLine(message: string): string {
  return message.split("\n").map((line) => line.trim()).filter(Boolean).join(" ");
}

export async function cmdFlag(pseudonymHex?: string) {
  const { d } = contracts();
  const tm = wallet(DEPLOYER_PK); // the TM is the deployer in this demo
  // Flag a specific pseudonym when given (e.g. an issuer flagging a securityholder row);
  // otherwise default to the demo sender's token pseudonym (the CLI story).
  const ps = pseudonymHex ? A(pseudonymHex) : await pseudonymFor(A(d.idRegime), A(d.regulatedToken), USER);
  console.log(bold("\n7. Transaction Monitor flags the sender's pseudonym") + dim("  (e.g. sanctions hit)"));
  const FLAG_SANCTIONS = 1n << 3n;
  const h = await tm.writeContract({ address: d.ordb as `0x${string}`, abi: abis.ordb, functionName: "flagPseudonym", args: [toHex32(ps), FLAG_SANCTIONS] });
  await txWait(h);
  console.log(green(`   ✓ pseudonym ${toHex32(ps).slice(0, 14)}… flagged (SANCTIONS_LINKED)`));
  console.log(dim("   the existing session runs until expiry; a NEW session can no longer be minted"));
  console.log(dim("   (no ORDB non-membership witness exists for a flagged pseudonym), try `make cli ARGS=session`\n"));
  return ps;
}

const program = new Command();
program.name("gap").description("GAP v2 local interaction CLI");
program.hook("preAction", async () => { await initIdentities(); }); // D6: derive did+salt from wallet keys
program.command("status").description("show deployment + both parties' state").action(() => cmdStatus());
program.command("onboard").description("register the sender's DID + issue credentials").action(() => cmdOnboard(USER, "•"));
program.command("onboard-recipient").description("register the recipient's DID + issue credentials").action(() => cmdOnboard(RECEIVER, "•"));
program.command("session")
  .option("--grant-only", "stop after the holder's grant, leaving the session unattested")
  .description("sender proves eligibility + opens a User Session")
  .action(async (o: { grantOnly?: boolean }) => {
    const { d } = contracts();
    await cmdSession(USER, d.policyId, "•", "User Session", undefined,
      o.grantOnly ? { monitorAttests: false } : {});
  });
program.command("session-second-wallet")
  .description("the SAME person opens a session from their second account wallet")
  .action(async () => {
    const { d } = contracts();
    await cmdSession(walletOf(USER, USER.accounts[1].address), d.policyId, "•", "User Session");
  });
program.command("receiving-session").description("recipient opens a receiving session (GAP-H6)").action(async () => {
  const { d } = contracts(); await cmdSession(RECEIVER, d.receivingPolicyId, "•", "receiving session");
});
program.command("transfer").argument("[amount]", "amount", "100").description("regulated token transfer").action((a) => cmdTransfer(a, "•"));
// The other half of a grant, on its own. In the ordinary story `session` does both and this
// reports "already attested"; it exists for the browser/sidecar path, where the holder's wallet
// grants and the monitor attests as separate acts, and so that a reader can run the monitor's
// step and see that it needs no part of the holder's proof.
program.command("attest")
  .argument("[party]", "sender|recipient", "sender")
  .description("the Transaction Monitor attests a pending session (the other half of a grant)")
  .action(async (party: string) => {
    const { d } = contracts();
    const recipient = party === "recipient";
    await attestSessionAsMonitor(
      recipient ? RECEIVER : USER,
      recipient ? d.receivingPolicyId : d.policyId,
    );
  });
program.command("flag").description("TM flags the sender's pseudonym").action(async () => { await cmdFlag(); });
/**
 * ACT 2: the permissioned AMM. Separate from `demo` on purpose: the pool layer is additive, so the
 * token story must still run on a deployment that has no DEX. Requires `make dex-up`.
 */
export async function cmdPoolStory() {
  const { dexDeploymentIfLive } = await import("./state");
  const pool = await import("./pool");
  // Presence on disk is not presence on chain: `up` leaves an earlier run's deployment file
  // behind, and running the acts against dead addresses fails as a contract error rather than as
  // the stale artifact it is. The two cases are reported separately because the fix differs.
  const live = await dexDeploymentIfLive();
  if (!live) {
    console.log(dim("\n(no permissioned pool deployed, run `make dex-up` to include this act)"));
    return;
  }
  if ("stale" in live) {
    console.log(dim("\n(the pool deployment on file is from an earlier chain: its contracts have no"));
    console.log(dim(" code here. Run `make dex-up` to redeploy it, or delete"));
    console.log(dim(" contracts/deployments/31337-dex.json to skip this act.)"));
    return;
  }
  const { d } = contracts();
  const symbol = "dNMS"; // the pool trades a tokenized listed equity, not the fund token

  console.log(bold("\nP1. A THIRD scope: the tokenized equity") + dim("  (the exemption's subject is NMS stock, and it carries its own filter)"));
  await pool.equitySession(USER, "P1a");
  console.log(bold("P1b. And the POOL's own scope") + dim("  (the equity session does not admit anyone to the venue either)"));
  await pool.poolSession(USER, "liquidity", "P1b");
  console.log(bold("P2. Seed the pool") + dim("  (the pool holds the equity under a Compliant DEX Classification Credential, not a user session)"));
  await pool.poolFund(USER, 500_000n * 10n ** 6n);
  const added = await pool.poolAddLiquidity(USER, 100_000n * 10n ** 18n, 100_000n * 10n ** 6n);
  if (added.outcome !== "added") throw new Error(`liquidity unexpectedly blocked: ${added.reason}`);
  console.log(green("   ✓ liquidity added") + dim(` (gas ${added.gasUsed}), LP position is a non-transferable balance, so there is no wrapper to look through`));

  console.log(bold("P3. A swap by an unsessioned trader") + dim("  (should be refused at the pool's own filter)"));
  const blocked = await pool.poolSwap(RECEIVER, false, 1000n * 10n ** 6n);
  if (blocked.outcome !== "blocked") { console.log(red("   ✗ unexpected: swap succeeded without a pool session")); }
  else console.log(green("   ✓ swap correctly refused: ") + dim(blocked.reason));

  console.log(bold("P4. Buying needs the POOL's own session, on top of the equity's") + dim("  (two scopes, two proofs, neither admits you to the other)"));
  const preBuy = await pool.poolSwap(USER, false, 1000n * 10n ** 6n);
  if (preBuy.outcome === "swapped") console.log(red("   ✗ unexpected: bought the security with no pool swap session"));
  else console.log(green("   ✓ refused before any pool session: ") + dim(preBuy.reason));
  await pool.poolSession(USER, "swap", "P4a");
  console.log(dim("   and the swap proves a THRESHOLD, not an equality: evidence tier >= 3, the value never shown."));
  console.log(dim("   Settlement will still run the EQUITY's own gate on both legs: the P1a session covers"));
  console.log(dim("   the holder as recipient, and the pool passes as a classified contract."));

  console.log(bold("P5. The swap settles") + dim("  (the POOL is the sender of a gated equity, only its Contract Session permits that)"));
  const swapped = await pool.poolSwap(USER, false, 1000n * 10n ** 6n);
  if (swapped.outcome !== "swapped") throw new Error(`swap unexpectedly blocked: ${swapped.reason}`);
  console.log(green("   ✓ swap settled") + dim(` (gas ${swapped.gasUsed}), ${swapped.amountOut} ${symbol} out`));

  console.log(bold("P6. The pool's OWN monitor flags the holder") + dim("  (market-integrity surface, independent of the token's AML/CFT ORDB)"));
  const ps = await pool.poolFlag(USER);
  console.log(green(`   ✓ pool pseudonym ${toHex32(ps).slice(0, 14)}… flagged (MARKET_ABUSE)`));
  console.log(dim("   the holder's TOKEN sessions are untouched: that separation is what per-contract pseudonyms buy"));
  const st = await pool.poolStatus(USER);
  console.log(dim(`   reserves ${st.securityReserve} ${symbol} / ${st.cashReserve} dUSD · checker flags ${st.checkerFlags}`));
}

program.command("pool-story").description("the permissioned-AMM act (requires make dex-up)").action(() => cmdPoolStory());
program.command("disclosure").description("what the chain saw about the sender, and what it never saw").action(async () => {
  const { cmdDisclosure } = await import("./disclosure");
  await cmdDisclosure(USER);
});
program.command("policy-floor").description("show a one-person predicate being refused at registration").action(async () => {
  const { cmdPolicyFloor } = await import("./disclosure");
  await cmdPolicyFloor("•");
});
program.command("unmask").description("the Identity Keeper resolves the sender's flagged pseudonym to a DID (§5.4)").action(async () => {
  const { d } = contracts();
  const { cmdUnmask } = await import("./disclosure");
  const ps = await pseudonymFor(A(d.idRegime), A(d.regulatedToken), USER);
  await cmdUnmask(ps, d.regulatedToken as `0x${string}`, "the fund token");
});

program.command("demo").description("the full two-party story: gate both sides, then flag").action(async () => {
  const { d } = contracts();
  await cmdStatus();
  await cmdOnboard(USER, "1");
  await cmdSession(USER, d.policyId, "2", "User Session");
  await cmdTransfer("100", "3", true); // GAP-H6: blocked, recipient holds no receiving session
  await cmdOnboard(RECEIVER, "4");
  await cmdSession(RECEIVER, d.receivingPolicyId, "5", "receiving session");
  await cmdTransfer("100", "6");
  // One person, many wallets: the sender's SECOND account wallet proves a session
  // under the SAME DID, salt and pseudonym: no second onboarding, no second DID.
  await cmdSession(
    walletOf(USER, USER.accounts[1].address), d.policyId, "6b",
    "User Session from the same person's 2nd wallet",
  );
  await cmdPoolStory(); // ACT 2, before the flag, which blocks any NEW token session
  const { cmdPolicyFloor, cmdDisclosure, cmdUnmask } = await import("./disclosure");
  await cmdPolicyFloor("6c");
  const flagged = await cmdFlag();
  await cmdUnmask(flagged, d.regulatedToken as `0x${string}`, "the fund token");
  console.log(bold("8. Sender proves again after the flag, should FAIL to open a session:"));
  try { await cmdSession(USER, d.policyId, "8", "User Session"); console.log(red("   unexpected: session opened despite flag")); }
  catch (e: any) { console.log(green("   ✓ session correctly rejected: ") + dim((e.message || "").split("\n")[0]) + "\n"); }
  await cmdStatus();
  await cmdDisclosure(USER); // ACT 3: the ledger: say exactly what was and was not disclosed
});
// Only run the CLI when executed directly, sidecar.ts imports the cmd* functions and must not
// trigger commander with its own argv.
if (process.argv[1]?.endsWith("cli.ts")) {
  // The explicit exit is load-bearing, not tidiness. snarkjs leaves worker threads alive after a
  // proof, so any command that proves finishes its story and then never returns to the prompt, 
  // `make demo` completed all its assertions and sat there until killed. stdout is flushed
  // first, because process.exit() will not wait for a pending write to a pipe.
  program.parseAsync()
    .then(async () => {
      await new Promise<void>((resolve) => process.stdout.write("", () => resolve()));
      process.exit(0);
    })
    .catch((e) => { console.error(red("Error:"), e.message || e); process.exit(1); });
}
