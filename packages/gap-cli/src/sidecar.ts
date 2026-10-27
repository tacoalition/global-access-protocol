#!/usr/bin/env tsx
// GAP v2 Phase-0 sidecar entrypoint (UI_INTEGRATION_ANALYSIS.md (full stack, not in this repository) §4): a JSON verb
// surface over the REAL demo flows, for the gap-interactive-demo UI's API routes to shell.
// Reuses cli.ts / prover.ts / state.ts verbatim, same proofs, same txs, same reverts.
// Contract: JSON on stdout (single line), human logs diverted to stderr, exit 0 = verb ok.
import { contracts, initIdentities, USER, RECEIVER, DemoIdentity, toHex32, ZoneId, ZONES } from "./state";
import { pseudonymFor } from "./prover";
import { cmdOnboard, cmdSession, cmdTransfer, cmdFlag, prepareSession, submitSession } from "./cli";
import * as fs from "node:fs";
import { venueSession, venueIssue, venueTransfer, venuePreflight, venueStatus } from "./venue";
import { buildHolderFile, getAuditLog, resolveOne } from "./referral";
import { inspectNamedSession } from "@tac-gap/sdk";

// stdout is the machine channel. The reused flows write human logs via BOTH console.log and
// process.stdout.write (the "generating proof…" progress), divert every one of them to stderr so
// stdout carries ONLY our JSON result. `emit` uses the captured original stdout writer.
const rawStdoutWrite = process.stdout.write.bind(process.stdout);
console.log = (...args: unknown[]) => console.error(...args);
process.stdout.write = ((chunk: string | Uint8Array, ...rest: unknown[]) =>
  (process.stderr.write as (c: string | Uint8Array, ...r: unknown[]) => boolean)(chunk, ...rest)) as typeof process.stdout.write;
const emit = (o: unknown) => rawStdoutWrite(JSON.stringify(o) + "\n");

const A = (x: string): bigint => BigInt(x);

function identityFor(name: string): DemoIdentity {
  if (name === "user") return USER;
  if (name === "recipient") return RECEIVER;
  throw new Error(`unknown identity '${name}' (use user|recipient)`);
}

async function partyStatus(id: DemoIdentity, policyId: string) {
  const { d, did, ordb, sm, token } = contracts();
  const registered = await did.read.isRegistered([toHex32(id.did)]);
  const balance = (await token.read.balanceOf([id.address])) as bigint;
  // Report the session the CONTRACT names, not whatever is in the live slot. This verb runs
  // straight after `cmdSession`, and a re-grant behind a live attested session is STAGED
  // (SessionManager._install), off the live slot this claimed the just-granted session was
  // already attested, with the PREVIOUS session's expiry.
  const pid = policyId as `0x${string}`;
  const [live, pending, named] = await Promise.all([
    sm.read.getSession([id.address, pid]),
    sm.read.getPendingSession([id.address, pid]),
    sm.read.sessionDigestOf([id.address, pid]),
  ]);
  const session = inspectNamedSession(
    id.address,
    { live: live as any, pending: pending as any, named: named as `0x${string}` },
  );
  // `hasValidSession` is the LIVE slot by contract design: it is the gate the TransactionFilter
  // enforces, so it stays live even while a renewal is staged behind it.
  const active = await sm.read.hasValidSession([id.address, pid, d.regulatedToken as `0x${string}`]);
  const ps = await pseudonymFor(A(d.idRegime), A(d.regulatedToken), id);
  const flagged = await ordb.read.isFlagged([toHex32(ps)]);
  return {
    address: id.address,
    registered,
    balance: balance.toString(),
    flagged,
    session: {
      granted: session.present,
      attested: session.attested,
      active,
      /** True when the named session is a staged renewal awaiting promotion by the TM. */
      staged: session.staged,
      validUntil: Number(session.session.validUntil),
    },
  };
}

async function verbStatus() {
  const { d } = contracts();
  return {
    ok: true,
    deployment: {
      sessionManager: d.sessionManager, regulatedToken: d.regulatedToken, ordb: d.ordb,
      venue: d.venue ?? null, policyId: d.policyId, receivingPolicyId: d.receivingPolicyId,
    },
    user: await partyStatus(USER, contracts().d.policyId),
    recipient: await partyStatus(RECEIVER, contracts().d.receivingPolicyId),
  };
}

/// Real pre-flight, straight off the chain views the token itself consults (TF check +
/// checkRecipient): this is what the UI's "checking recipient eligibility…" beat reads.
async function verbPreflight() {
  const { d } = contracts();
  const { createPublicClient, http } = await import("viem");
  const pc = createPublicClient({ transport: http(process.env.RPC_URL || "http://127.0.0.1:8545") });
  const tfAbi = [
    { type: "function", name: "check", stateMutability: "view", inputs: [{ type: "bytes4" }, { type: "address" }, { type: "address" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "checkRecipient", stateMutability: "view", inputs: [{ type: "bytes4" }, { type: "address" }], outputs: [{ type: "bool" }] },
  ] as const;
  const transferSelector = "0xa9059cbb" as `0x${string}`; // transfer(address,uint256)
  const senderOk = await pc.readContract({ address: d.transactionFilter as `0x${string}`, abi: tfAbi, functionName: "check", args: [transferSelector, USER.address, "0x0000000000000000000000000000000000000000"] });
  const recipientOk = await pc.readContract({ address: d.transactionFilter as `0x${string}`, abi: tfAbi, functionName: "checkRecipient", args: [transferSelector, RECEIVER.address] });
  return { ok: true, senderOk, recipientOk };
}

async function main() {
  const [verb, ...args] = process.argv.slice(2);
  await initIdentities(); // D6: derive USER/RECEIVER did+salt from their wallet signatures
  const { d } = contracts();
  switch (verb) {
    case "status":
      emit(await verbStatus());
      break;
    case "onboard": {
      const id = identityFor(args[0] ?? "user");
      await cmdOnboard(id, "•");
      emit({ ok: true, identity: args[0] ?? "user", did: toHex32(id.did) });
      break;
    }
    case "session": {
      const id = identityFor(args[0] ?? "user");
      const kind = args[1] ?? (id === USER ? "transfer" : "receiving");
      const policyId = kind === "receiving" ? d.receivingPolicyId : d.policyId;
      await cmdSession(id, policyId, "•", `${kind} session`); // proves + grants + TM-attests (real)
      const status = await partyStatus(id, policyId);
      emit({ ok: true, identity: args[0] ?? "user", kind, session: status.session });
      break;
    }
    case "transfer": {
      const amount = args[0] ?? "100";
      // Probe the real chain views first so the expectation (and the failure reason) is honest.
      const pf = await verbPreflight();
      if (!pf.senderOk) {
        emit({ ok: true, outcome: "blocked", reason: "sender has no active session", amount, preflight: pf });
        break;
      }
      await cmdTransfer(amount, "•", !pf.recipientOk); // recipient-side block is a real revert
      emit({
        ok: true,
        outcome: pf.recipientOk ? "sent" : "blocked",
        reason: pf.recipientOk ? undefined : "recipient not compliant (no receiving session)",
        amount, preflight: pf,
      });
      break;
    }
    case "preflight":
      emit(await verbPreflight());
      break;
    case "flag":
      await cmdFlag(args[0]); // optional pseudonym hex, flag a specific securityholder
      emit({ ok: true, flagged: true });
      break;

    // ── venue verbs (RegulatedVenueV2, D1) ──
    case "venue-status":
      emit({ ok: true, ...(await venueStatus()) });
      break;
    case "venue-session": {
      const id = identityFor(args[0] ?? "user");
      const zone = (args[1] ?? "general") as ZoneId;
      const kind = (args[2] ?? (id === USER ? "transfer" : "receiving")) as "transfer" | "receiving";
      if (!ZONES[zone]) throw new Error(`unknown zone '${zone}' (general|reg-d)`);
      await venueSession(id, zone, kind);
      emit({ ok: true, identity: args[0] ?? "user", zone, kind });
      break;
    }
    case "venue-issue": {
      const zone = (args[0] ?? "general") as ZoneId;
      const id = identityFor(args[1] ?? "user");
      const amount = BigInt(args[2] ?? "1000");
      if (!ZONES[zone]) throw new Error(`unknown zone '${zone}'`);
      await venueIssue(zone, id, amount);
      emit({ ok: true, zone, to: args[1] ?? "user", amount: amount.toString() });
      break;
    }
    case "venue-preflight": {
      const zone = (args[0] ?? "general") as ZoneId;
      if (!ZONES[zone]) throw new Error(`unknown zone '${zone}'`);
      emit({ ok: true, zone, ...(await venuePreflight(zone)) });
      break;
    }
    case "venue-transfer": {
      const zone = (args[0] ?? "general") as ZoneId;
      const amount = BigInt(args[1] ?? "100");
      if (!ZONES[zone]) throw new Error(`unknown zone '${zone}'`);
      const res = await venueTransfer(zone, amount);
      emit({ ok: true, zone, amount: amount.toString(), ...res });
      break;
    }

    // ── browser-proving split (#17): build the input here, prove in the browser, submit here ──
    case "session-input": {
      const id = identityFor(args[0] ?? "user");
      const kind = args[1] ?? (id === USER ? "transfer" : "receiving");
      const policyId = kind === "receiving" ? d.receivingPolicyId : d.policyId;
      const prep = await prepareSession(id, policyId, kind);
      emit({ ok: true, input: prep.input, ciphertext: prep.ciphertext,
        validUntil: prep.validUntil.toString(), version: prep.version, policyId: prep.policyId, kind });
      break;
    }
    case "session-submit": {
      // the API route wrote the browser-generated proof + meta to a temp file; args[0] is its path.
      const payload = JSON.parse(fs.readFileSync(args[0], "utf8"));
      const id = identityFor(payload.identity);
      const big = (a: any): any => Array.isArray(a) ? a.map(big) : BigInt(a);
      await submitSession(id, payload.policyId, BigInt(payload.validUntil), Number(payload.version),
        big(payload.pA), big(payload.pB), big(payload.pC), big(payload.pub), payload.ciphertext);
      emit({ ok: true, submitted: true });
      break;
    }

    // ── indexer + IK referral (Master Securityholder File, #19/D4) ──
    case "holder-file": {
      if (args[0] === "resolve-one") { // real per-holder referral for one pseudonym (audit-logged)
        const { holder, audit } = await resolveOne(args[1]);
        emit({ ok: true, holder, audit });
        break;
      }
      const resolveAll = args[0] === "resolve";
      const { holders, audited } = await buildHolderFile(resolveAll);
      emit({ ok: true, holders, resolved: resolveAll, auditEntries: audited, audit: getAuditLog() });
      break;
    }
    default:
      throw new Error(`unknown verb '${verb}' (status|onboard|session|transfer|preflight|flag|venue-*)`);
  }
}

main().then(() => process.exit(0)).catch((e) => {
  emit({ ok: false, error: String(e?.message ?? e).split("\n")[0] });
  process.exit(1);
});
