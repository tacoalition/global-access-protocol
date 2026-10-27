// Node reference for the on-chain witness reader (the browser has its own viem-based copy).
// Fetches everything needed to assemble a session witness from PUBLIC chain data + the on-chain
// merkle-proof views: no holder mirror. Used by the parity check to prove the browser path
// produces the exact same input as the server's holder-mirror path.
import { rememberMonitorKey } from "./monitor-key";
import { accountsOf, contracts, ordbAt, DemoIdentity, toHex32, CHAIN_ID } from "./state";
import { pseudonymFor } from "./prover";
import { walletSetWitness } from "./wallet-set";
import { ATTRS } from "./cli";
import type { WitnessData } from "@tac-gap/sdk";
import type { SessionTarget } from "./cli";

const A = (x: string | bigint): bigint => BigInt(x);

export async function fetchWitness(id: DemoIdentity, policyId: string, validUntil: bigint, target: SessionTarget): Promise<WitnessData> {
  const { d, did, ita, sm, policy } = contracts();
  const ordb = ordbAt(target.ordbAddress);
  const nonce = (await sm.read.sessionNonce([id.address])) as bigint;
  // UserPolicyRegistry.latestVersion returns uint32, so viem hands back a number here.
  const policyVersion = BigInt(await policy.read.latestVersion([policyId as `0x${string}`]));
  const [mkX, mkY, keyId] = await ordb.read.getMonitorKey();
  // Record the POINT, not just the id. The prover seals to whatever the chain declares; discarding
  // the point here is what let a rotated key produce envelopes no monitor could open.
  rememberMonitorKey(BigInt(keyId as string | bigint), BigInt(mkX as string | bigint), BigInt(mkY as string | bigint));
  const didRoot = await did.read.root();
  const credRoot0 = await ita.read.getAttributeRegimeRoot([d.idRegime as `0x${string}`]);
  const credRoot1 = await ita.read.getAttributeRegimeRoot([d.invRegime as `0x${string}`]);
  const c0 = (await ita.read.getCredential([d.idRegime as `0x${string}`, toHex32(id.did)])) as any;
  const c1 = (await ita.read.getCredential([d.invRegime as `0x${string}`, toHex32(id.did)])) as any;
  const [didSiblings, didIndex] = (await did.read.getMerkleProof([toHex32(id.did)])) as [readonly string[], bigint];
  const [c0Siblings, c0Index] = (await ita.read.getCredentialProof([d.idRegime as `0x${string}`, toHex32(id.did)])) as [readonly string[], bigint];
  const [c1Siblings, c1Index] = (await ita.read.getCredentialProof([d.invRegime as `0x${string}`, toHex32(id.did)])) as [readonly string[], bigint];
  const ps = await pseudonymFor(A(d.idRegime), A(target.gatedContract), id);
  const [lowIndex, lowKey, nextKey, rdbSiblings, riskRoot] =
    (await ordb.read.getNonMembershipWitness([toHex32(ps)])) as [bigint, string, string, readonly string[], string];

  return {
    did: id.did, privateSalt: id.privateSalt, account: A(id.address), attrs: ATTRS,
    credExpiresAt: [c0.expiresAt, c1.expiresAt], ikId0: A(d.ikId), ikId1: A(d.ikId),
    ita0: A(d.identityAnchor), ita1: A(d.identityAnchor),
    regime0: A(d.idRegime), regime1: A(d.invRegime),
    sessionManager: A(d.sessionManager), chainId: BigInt(CHAIN_ID), policyId: A(policyId),
    policyVersion,
    validUntil, accountNonce: nonce, gatedContract: A(target.gatedContract), ordbId: A(target.ordbAddress),
    monitorKeyId: A(keyId as string), clauses: target.clauses,
    didRoot: A(didRoot as string), credRoot0: A(credRoot0 as string), credRoot1: A(credRoot1 as string),
    didSiblings: didSiblings.map(A), didIndex: Number(didIndex),
    // The wallet set is holder-side state, not chain state: the DID document pins only
    // its root. The witness has to come from the person's own record, and it must be the
    // SAME root the DID leaf was folded from or this input proves nothing.
    spendingKeyWitness: await walletSetWitness(accountsOf(id), id.address, id.privateSalt),
    cred0Siblings: c0Siblings.map(A), cred0Index: Number(c0Index),
    cred1Siblings: c1Siblings.map(A), cred1Index: Number(c1Index),
    rdb: { root: A(riskRoot), lowKey: A(lowKey), nextKey: A(nextKey), siblings: rdbSiblings.map(A), index: Number(lowIndex) },
  };
}
