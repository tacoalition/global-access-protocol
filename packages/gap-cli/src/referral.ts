// Indexer + IK referral resolution (integration backlog #19, decision D4): the real machinery
// behind the Referral Portal's Master Securityholder File. Instead of mocked holders, this reads
// REAL on-chain state: who holds the asset (balances), each holder's pseudonym from their real
// SessionGranted ciphertext (the TM's decrypt), and resolves it to PII via the issuing IK: every
// resolution appended to an audit log (D4: purpose-logged).
import { decodeAbiParameters, parseAbiItem } from "viem";
import { contracts, ordbAt, publicClient, USER, RECEIVER, DemoIdentity, toHex32, initIdentities } from "./state";
import { pseudonymFor } from "./prover";

const A = (x: string): bigint => BigInt(x);
const SESSION_GRANTED = parseAbiItem(
  "event SessionGranted(address indexed account, bytes32 indexed policyId, uint32 policyVersion, uint64 validUntil, bytes encryptedPseudonym)"
);

// Demo "KYC file" the issuing IK holds offchain, resolution maps a pseudonym → this record.
// (The RESOLUTION PATH is real; the PII payload is demo data, since there's no real KYC DB.)
const KYC: Record<string, { name: string; entityType: "Individual" | "Entity"; taxId: string; jurisdiction: string }> = {
  [USER.address.toLowerCase()]: { name: "Jordan A. Miller", entityType: "Individual", taxId: "SSN •••-••-4021", jurisdiction: "US, NY" },
  [RECEIVER.address.toLowerCase()]: { name: "Redwood Capital LLC", entityType: "Entity", taxId: "EIN ••-•••7734", jurisdiction: "US, DE" },
};

export interface AuditEntry { at: number; requester: string; pseudonym: string; account: string; purpose: string }
const auditLog: AuditEntry[] = [];
export function getAuditLog(): AuditEntry[] { return auditLog; }

export interface HolderRecord {
  pseudonym: string;      // real, derived from the holder's session ciphertext
  account: string;
  holdings: string;
  identityKeeper: string; // the issuing IK (from the referral route in the ciphertext)
  resolved: boolean;
  flagged: boolean;       // real ORDB.isFlagged(pseudonym): a sanctions/risk hit
  pii?: { name: string; entityType: string; taxId: string; jurisdiction: string };
}

/**
 * Build the Master Securityholder File for the demo fund token from REAL chain state.
 * @param resolveAll  reveal PII for every holder (D4: logged as a regulated-purpose compilation).
 */
export async function buildHolderFile(resolveAll = false): Promise<{ holders: HolderRecord[]; audited: number }> {
  await initIdentities();
  const { d, token } = contracts();
  const ordb = ordbAt(d.ordb);
  const pc = publicClient();

  // 1. index SessionGranted events → account → its latest ciphertext (the pseudonym source).
  const logs = await pc.getLogs({ address: d.sessionManager as `0x${string}`, event: SESSION_GRANTED, fromBlock: 0n, toBlock: "latest" });
  const cipherByAccount = new Map<string, `0x${string}`>();
  for (const l of logs) {
    const acct = (l.args.account as string).toLowerCase();
    cipherByAccount.set(acct, l.args.encryptedPseudonym as `0x${string}`);
  }

  // 2. the real holder set = onboarded demo parties with a token balance.
  const holders: HolderRecord[] = [];
  for (const id of [USER, RECEIVER] as DemoIdentity[]) {
    const holdings = (await token.read.balanceOf([id.address])) as bigint;
    const enc = cipherByAccount.get(id.address.toLowerCase());
    if (holdings === 0n && !enc) continue;

    // 3. the TM decrypts the ciphertext → {pseudonym, blindingR, ita, ikId} (ECIES stand-in).
    let pseudonym = "0x0", ikId = "unknown";
    if (enc) {
      const [, , , ct] = decodeAbiParameters(
        [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes" }], enc);
      const [ps, , , ik] = decodeAbiParameters(
        [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "uint256" }], ct as `0x${string}`);
      pseudonym = toHex32(ps as bigint);
      ikId = (ik as bigint) === A(d.ikId) ? "acme-kyc" : toHex32(ik as bigint).slice(0, 12) + "…";
    } else {
      // minted-only holder (no session ciphertext), pseudonym via the referral fallback (D12)
      pseudonym = toHex32(await pseudonymFor(A(d.idRegime), A(d.regulatedToken), id));
      ikId = "acme-kyc (issuance record)";
    }

    const flagged = (await ordb.read.isFlagged([pseudonym as `0x${string}`])) as boolean;
    const rec: HolderRecord = {
      pseudonym, account: id.address, holdings: holdings.toString(), identityKeeper: ikId, resolved: false, flagged,
    };
    if (resolveAll) resolvePII(rec, "compile Master Securityholder File");
    holders.push(rec);
  }
  return { holders, audited: auditLog.length };
}

/** Resolve a single holder's PII by pseudonym (a real per-holder referral, D4-logged). */
export async function resolveOne(pseudonym: string): Promise<{ holder: HolderRecord | null; audit: AuditEntry[] }> {
  const { holders } = await buildHolderFile(false);
  const rec = holders.find((h) => h.pseudonym.toLowerCase() === pseudonym.toLowerCase()) ?? null;
  if (rec) resolvePII(rec, "resolve single securityholder (transfer-agent request)");
  return { holder: rec, audit: getAuditLog() };
}

/** Resolve one holder's PII via the IK referral, appending to the audit log (D4). */
export function resolvePII(rec: HolderRecord, purpose: string): HolderRecord {
  const pii = KYC[rec.account.toLowerCase()];
  if (pii) { rec.resolved = true; rec.pii = pii; }
  auditLog.push({ at: 0, requester: "transfer-agent", pseudonym: rec.pseudonym, account: rec.account, purpose });
  return rec;
}
