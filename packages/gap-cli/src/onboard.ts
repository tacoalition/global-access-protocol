// The v2 CLI lane's onboarding step: register a DID, then mint the two credentials
// the session circuit consumes.
//
// Extracted from cli.ts so the mint path: the only place in this lane that
// writes a credential, reads as one thing. EVERY `issueCredential` below is
// preceded by its own `assertIdentityCredentialMintAllowed` call, and each of
// those calls sees ALL FOUR attributes. See mint-guard.ts for why.
import {
  abis, accountsOf, contracts, DemoIdentity, DEPLOYER_PK, publicClient, toHex32, wallet,
} from "./state";
import { credentialCommitment, saltCommitment } from "./prover";
import { walletSetRoot } from "./wallet-set";
import { assertIdentityCredentialMintAllowed, investorCredentialExpiresAt } from "./mint-guard";
import { bold, dim, green } from "./ui";
import { txWait } from "./tx";

const A = (x: string): bigint => BigInt(x);

/**
 * This demo issues NO credential metadata. The field exists for an Identity Trust Anchor doing
 * Appendix III Sybil detection, "has this person already been issued under this anchor?", and it is
 * PUBLIC and permanent, so a bare hash of a low-entropy identifier is a dictionary attack away from
 * being the identifier. Nothing here needs it, so nothing here sets it.
 */
const NO_CREDENTIAL_METADATA = `0x${"0".repeat(64)}` as const;

// The demo attributes the IK certifies (identical for both parties: one shared eligibility bar).
// GAP_ATTR_CRED_V3 vocabulary: FOUR attributes per regime, two regimes.
//   [0..3] are the KYC provider's to attest: residency, sanctions, citizenship, reserved
//   [4..7] are the fund IK's:                accredited, qualified purchaser, evidenceTier, reserved
// Residency and citizenship are DISTINCT indices: attrs[0] is where the person lives, attrs[2] is
// what they are a national of. They are equal for this demo holder and deliberately not the same
// slot, see docs/ATTRIBUTE_ENCODING.md.
export type Attrs = [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
// attrs[6] is the evidence TIER behind the accredited determination (1..5 per
// EVIDENCE_TIER_BY_BASIS). 3 = NET_WORTH, a documented balance sheet. It is the one attribute a
// venue gates with a THRESHOLD rather than an equality, so a holder proves their determination rests
// on evidence at least as strong as the bar without revealing which basis it was.
export const ATTRS: Attrs = [840n, 0n, 840n, 0n, 1n, 1n, 3n, 0n];

/** The four attributes of one regime: regime 0 is attrs[0..3], regime 1 is attrs[4..7]. */
export function regimeAttrs(attrs: Attrs, regime: 0 | 1): [bigint, bigint, bigint, bigint] {
  const base = regime * 4;
  return [attrs[base], attrs[base + 1], attrs[base + 2], attrs[base + 3]];
}

export const CLAUSES = [
  { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n },  // residency == USA
  { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },    // not sanctioned
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
];

export async function cmdOnboard(id: DemoIdentity, step: string) {
  const { d } = contracts();
  const ik = wallet(DEPLOYER_PK); // the IK control key is the deployer in this demo
  const party = wallet(id.pk);
  const chainId = await publicClient().getChainId();
  // TWO credentials are written below, so the guard runs TWICE, once ahead of
  // each `issueCredential`. Each call checks all EIGHT attributes (the KYC
  // provider's residency/sanctions/citizenship AND the fund IK's accredited/QP
  // determination), so neither leaf can be minted outside the guard's view.
  const guarded = { chainId, did: toHex32(id.did), attributes: ATTRS } as const;
  await assertIdentityCredentialMintAllowed({ ...guarded, leaf: "identity" });
  console.log(bold(`\n${step}. Onboard the ${id.label}`) + dim("  (only commitments go on-chain; the salt never leaves the wallet)"));
  const psc = toHex32(await saltCommitment(id));
  // The AUTHORITATIVE wallet-set root over EVERY wallet this person owns, not a
  // singleton over the wallet that happens to be registering. This is what lets the
  // person's other account wallets open sessions under the same DID.
  const skRoot = await walletSetRoot(accountsOf(id), id.privateSalt);
  // COMMIT, then reveal in a later block. The commitment binds every field AND the registrant, so
  // a mempool watcher who sees the reveal cannot land the same DID under their own governance key:
  // they would need a commitment of their own from an earlier block, and the DID was secret until
  // this reveal. Two transactions is the whole cost.
  //
  // REGISTERED FROM THE GOVERNANCE KEY, NOT A SPENDING WALLET. Governance keys are stored in the
  // clear and `registerDID` requires the caller to be one of them, so registering from the wallet
  // that holds the asset would publish `DID -> wallet` to anyone with no keys: the exact link this
  // demo's closing panel calls the privacy claim. A reviewer read it off the chain with one call.
  // `id.governance` is in no spending set and holds nothing.
  const gov = wallet(id.governance.pk);
  const commitment = await publicClient().readContract({
    address: d.didRegistry as `0x${string}`, abi: abis.did, functionName: "registrationCommitment",
    args: [toHex32(id.did), psc, toHex32(skRoot), [id.governance.address], id.governance.address],
  }) as `0x${string}`;
  const h0 = await gov.writeContract({ address: d.didRegistry as `0x${string}`, abi: abis.did,
    functionName: "commitRegistration", args: [commitment] });
  await txWait(h0);
  const h1 = await gov.writeContract({ address: d.didRegistry as `0x${string}`, abi: abis.did, functionName: "registerDID",
    args: [toHex32(id.did), psc, toHex32(skRoot), [id.governance.address]] });
  await txWait(h1);
  console.log(green(`   ✓ DID ${toHex32(id.did).slice(0, 14)}…  spendingKeyRoot pinned over ${id.accounts.length} wallet(s)`));

  // expiresAt is folded into each leaf (GAP-H2): a session's validUntil must stay <= it, proven
  // in-circuit. Anchored to CHAIN time, not wall clock: the SM enforces against block.timestamp.
  const chainNow = (await publicClient().getBlock()).timestamp;
  const exp0 = chainNow + BigInt(7 * 24 * 3600);
  const c0 = toHex32(await credentialCommitment(A(d.identityAnchor), A(d.idRegime), A(d.ikId), regimeAttrs(ATTRS, 0), exp0, id));
  const h2 = await ik.writeContract({ address: d.identityAnchor as `0x${string}`, abi: abis.ita, functionName: "issueCredential",
    args: [d.idRegime as `0x${string}`, toHex32(id.did), c0, exp0, d.ikId as `0x${string}`, NO_CREDENTIAL_METADATA] });
  await txWait(h2);
  console.log(green("   ✓ Standard-Identity credential (resident USA, citizen USA, not-sanctioned), expires in 7 days"));

  // Second write, second guard call. exp1 is never 0n: investor status is a suitability
  // determination and a determination that never expires is a determination nobody is on the
  // hook for. The TTL is capped by the fund IK's own attestation lifetime (see mint-guard.ts).
  const investorAuth = await assertIdentityCredentialMintAllowed({ ...guarded, leaf: "investor" });
  const exp1 = investorCredentialExpiresAt({ chainNow, authorization: investorAuth });
  const c1 = toHex32(await credentialCommitment(A(d.identityAnchor), A(d.invRegime), A(d.ikId), regimeAttrs(ATTRS, 1), exp1, id));
  const h3 = await ik.writeContract({ address: d.identityAnchor as `0x${string}`, abi: abis.ita, functionName: "issueCredential",
    args: [d.invRegime as `0x${string}`, toHex32(id.did), c1, exp1, d.ikId as `0x${string}`, NO_CREDENTIAL_METADATA] });
  await txWait(h3);
  const days = Number(exp1 - chainNow) / 86400;
  console.log(green(`   ✓ Investor-Status credential (accredited, QP), expires in ${days.toFixed(1)} days`)
    + dim(investorAuth.suitabilityExpiresAt === undefined ? "  (UNATTESTED local fixture)" : "  (fund-IK attested)"));
}
