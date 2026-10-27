// Venue flows (RegulatedVenueV2, decision D1): sessions/transfers scoped to the VENUE across
// Regulated Zones, reusing the proven cmdSession grant+attest path with a venue target. The
// demo user's two credentials satisfy the General and Reg-D zones (see state.ts ZONES).
import { contracts, ordbAt, wallet, abis, USER, RECEIVER, DemoIdentity, DEPLOYER_PK, toHex32, publicClient, ZONES, ZoneId } from "./state";
import { pseudonymFor } from "./prover";
import { cmdSession, SessionTarget } from "./cli";

const A = (x: string): bigint => BigInt(x);

function targetFor(zone: ZoneId): SessionTarget {
  const { d } = contracts();
  return { gatedContract: d.venue, ordbAddress: d.venueOrdb, clauses: ZONES[zone].clauses };
}

/** Open + TM-attest a venue session for `zone` (transfer or receiving), reusing cmdSession. */
export async function venueSession(id: DemoIdentity, zone: ZoneId, kind: "transfer" | "receiving") {
  const { d } = contracts();
  const z = ZONES[zone];
  const policyId = kind === "transfer" ? (d as any)[z.transferKey] : (d as any)[z.receivingKey];
  await cmdSession(id, policyId, "•", `${z.label} ${kind}`, targetFor(zone));
}

/** Operator (TA/TM = deployer) issues a zone asset into a holder's venue balance. */
export async function venueIssue(zone: ZoneId, to: DemoIdentity, amount: bigint) {
  const { d } = contracts();
  const assetId = (d as any)[ZONES[zone].assetId] as `0x${string}`;
  const op = wallet(DEPLOYER_PK);
  const h = await op.writeContract({ address: d.venue as `0x${string}`, abi: abis.venue, functionName: "issue", args: [assetId, to.address, amount] });
  await publicClient().waitForTransactionReceipt({ hash: h });
}

/** Real venue transfer sender→recipient (both sides gated per the asset's zone). */
export async function venueTransfer(zone: ZoneId, amount: bigint) {
  const { d, venue } = contracts();
  const assetId = (d as any)[ZONES[zone].assetId] as `0x${string}`;
  const [senderOk, recipientOk] = await venue.read.preflight([assetId, USER.address, RECEIVER.address]);
  if (!senderOk) return { outcome: "blocked" as const, reason: "sender has no transfer session for this zone" };
  if (!recipientOk) return { outcome: "blocked" as const, reason: "recipient not compliant (no receiving session)" };
  const sender = wallet(USER.pk);
  const h = await sender.writeContract({ address: d.venue as `0x${string}`, abi: abis.venue, functionName: "transfer", args: [assetId, RECEIVER.address, amount] });
  await publicClient().waitForTransactionReceipt({ hash: h });
  return { outcome: "sent" as const };
}

export async function venuePreflight(zone: ZoneId) {
  const { d, venue } = contracts();
  const assetId = (d as any)[ZONES[zone].assetId] as `0x${string}`;
  const [senderOk, recipientOk] = await venue.read.preflight([assetId, USER.address, RECEIVER.address]);
  return { senderOk, recipientOk };
}

async function partyVenue(id: DemoIdentity, zone: ZoneId) {
  const { d, sm, venue } = contracts();
  const z = ZONES[zone];
  const assetId = (d as any)[z.assetId] as `0x${string}`;
  const balance = (await venue.read.balanceOf([assetId, id.address])) as bigint;
  const transferPol = (d as any)[z.transferKey] as `0x${string}`;
  const receivingPol = (d as any)[z.receivingKey] as `0x${string}`;
  const transferActive = await sm.read.hasValidSession([id.address, transferPol, d.venue as `0x${string}`]);
  const receivingActive = await sm.read.hasValidSession([id.address, receivingPol, d.venue as `0x${string}`]);
  const ps = await pseudonymFor(A(d.idRegime), A(d.venue), id);
  const flagged = await ordbAt(d.venueOrdb).read.isFlagged([toHex32(ps)]);
  return { address: id.address, balance: balance.toString(), transferActive, receivingActive, flagged };
}

/** Venue state for the UI: zones, assets, and both parties' balances + session flags. */
export async function venueStatus() {
  const { d } = contracts();
  const zones: Record<string, unknown> = {};
  for (const zone of Object.keys(ZONES) as ZoneId[]) {
    const z = ZONES[zone];
    zones[zone] = {
      label: z.label, asset: z.assetSymbol,
      user: await partyVenue(USER, zone),
      recipient: await partyVenue(RECEIVER, zone),
    };
  }
  return { venue: d.venue, venueOrdb: d.venueOrdb, zones };
}
