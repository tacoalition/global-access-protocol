// "What the chain saw, and what it never saw."
//
// This exists because the privacy claim is the easiest thing in this system to overstate. Every line
// below is READ FROM CHAIN or read from the holder's local witness: none of it is narration. The
// audited boundary it reports is docs/ON_CHAIN_DISCLOSURE.md; if the two disagree, that file
// and the contracts are right and this is a defect.
import { contracts, ordbAt, publicClient, abis, toHex32, DemoIdentity, loadDexDeployment } from "./state";
import { ATTRS } from "./onboard";
import { pseudonymFor } from "./prover";
import { bold, dim, green, red } from "./ui";

const short = (h: string, n = 10) => `${h.slice(0, n)}…${h.slice(-4)}`;

export async function cmdDisclosure(id: DemoIdentity) {
  const { d, did, ita, sm, policy, token } = contracts();
  const ordb = ordbAt(d.ordb);
  const didHex = toHex32(id.did);

  const [symbol, registered, cred, session, version] = await Promise.all([
    token.read.symbol(),
    did.read.isRegistered([didHex]),
    ita.read.getCredential([d.idRegime as `0x${string}`, didHex]),
    sm.read.getSession([id.address, d.policyId as `0x${string}`]),
    policy.read.latestVersion([d.policyId as `0x${string}`]),
  ]);
  const [, , , clausesHash] = await policy.read.getPolicyVersion([d.policyId as `0x${string}`, version]);
  const pseudonym = await pseudonymFor(BigInt(d.idRegime), BigInt(d.regulatedToken), id);
  const flagged = await ordb.read.isFlagged([toHex32(pseudonym)]);
  const s = session as any;

  console.log(bold(`\n── What the chain saw about the ${id.label} ──`)
    + dim("  (no keys, no privileged access: any observer)"));
  console.log(`   DID                 ${red(short(didHex, 14))} ` + dim("PLAINTEXT, and enumerable from DIDRegistered logs"));
  console.log(`   wallet              ${short(id.address, 14)} ` + dim("a public address, like any other"));
  console.log(`   credential exists   ${(cred as any).issuedAt !== 0n ? green("yes") : red("no")}`
    + dim(`  for standard-identity, expires ${new Date(Number((cred as any).expiresAt) * 1000).toLocaleTimeString()}`));
  console.log(`   credential content  ${dim(short((cred as any).commitment, 14))} `
    + dim("a COMMITMENT: the leaf, not the attributes"));
  console.log(`   session             ${s.attested ? green("attested") : dim("unattested")}`
    + dim(` until ${new Date(Number(s.validUntil) * 1000).toLocaleTimeString()}, scoped to ${short(s.gatedContract, 10)}`));
  console.log(`   the RULE it passed  ${dim(short(clausesHash, 14))} `
    + dim("clausesHash: the predicate is public, and curator-approved"));
  console.log(`   encrypted pseudonym ${dim(short(s.encryptedPseudonym as string, 14))} `
    + dim("opens only to the monitor key, whose scalar this demo publishes, so you can open it too"));
  console.log(`   flagged?            ${flagged ? red("yes") : green("no")}`
    + dim("  the flag SET is cleartext on purpose, non-membership needs a readable list"));

  console.log(bold(`\n── What it never saw ──`) + dim("  (these are private witnesses; they are in no public signal)"));
  console.log(`   which human         ${dim(", ")}  ` + dim("the wallet↔DID link is the privacy claim, and it is not on chain"));
  console.log(`   residency           ${dim(", ")}  ` + dim(`held locally as ${ATTRS[0]}, on chain only inside attrsHash`));
  console.log(`   citizenship         ${dim(", ")}  ` + dim(`held locally as ${ATTRS[2]}, a SEPARATE claim from residency`));
  // Precisely: attrs[1] IS the sanctions bit, it IS folded into attrsHash, and one of the two live
  // clauses gates on it being 0. What never happens is a credential carrying a POSITIVE hit: a hit
  // refuses issuance instead, so the bit is always 0 and therefore carries no information. Saying
  // "never encoded" was simply false, and this is the one panel that must not overstate.
  console.log(`   sanctions bit       ${dim("0")}  ` + dim("gated by a live clause; a positive hit refuses issuance, so it is always 0"));
  console.log(`   accredited / QP     ${dim(", ")}  ` + dim(`held locally as ${ATTRS[4]} / ${ATTRS[5]}, attested by the fund IK`));
  console.log(`   the salt            ${dim(", ")}  ` + dim("only its commitment is on chain, and that is immutable"));
  console.log(`   the pseudonym       ${dim(", ")}  ` + dim("only a blinded commitment and a ciphertext"));

  console.log(bold(`\n── The part that is easy to overstate ──`));
  console.log(dim("   The SET of wallets holding a session IS enumerable: SessionGranted is public and keyed"));
  console.log(dim("   by the account. GAP does not hide that a wallet is eligible. What it removes is the"));
  console.log(dim("   LINK and the COLLECTION: no venue holds a document, and no venue learns a name."));
  console.log(dim(`   A register-based venue would hold: ${symbol} holder list + KYC files + wallet→identity map.`));
  console.log(dim("   This one holds: none of the three. It asks a contract a question instead."));

  const dx = loadDexDeployment();
  if (dx) {
    const poolPseud = await pseudonymFor(BigInt(d.idRegime), BigInt(dx.gapCompliantDex), id);
    console.log(bold(`\n── One person, two venues, two names ──`));
    console.log(dim(`   token pseudonym  ${short(toHex32(pseudonym), 14)}`));
    console.log(dim(`   pool  pseudonym  ${short(toHex32(poolPseud), 14)}`));
    console.log(dim("   Same DID, same salt, same credentials, different venue, different name. Neither"));
    console.log(dim("   venue can link the PSEUDONYMS, and a flag at one does not follow to the other."));
    // The honest qualifier. This panel is headed "the part that is easy to overstate" and said, two
    // lines earlier, that the eligible set is enumerable by account, then claimed the venues cannot
    // link the holder. They can: this demo uses ONE wallet for both. The machinery for the stronger
    // claim exists and step 6b shows it; the demo simply does not use it here.
    console.log(dim("   The ACCOUNT still links them: one wallet, both venues. A holder who wants the"));
    console.log(dim("   venues unlinked uses a different wallet per venue (step 6b shows the machinery)."));
  }
  console.log("");
}

/**
 * The policy floor, demonstrated by a REFUSED TRANSACTION rather than a mapping lookup.
 *
 * The predicate attempted below is well formed in every respect: every clause is valid, the caller
 * is an authorised author. What makes it inadmissible is that it is NARROW: residency AND citizenship
 * AND accredited AND qualified purchaser is, in any real population, close to a one-person test. A
 * venue that could register it would learn its holder's identity from `SessionGranted` alone, because
 * clauses are public and session grants are public. Only curation stops that, and nothing about the
 * clause SHAPE could.
 */
export async function cmdPolicyFloor(step: string) {
  const { d, policy } = contracts();
  const { wallet, DEPLOYER_PK } = await import("./state");
  console.log(bold(`\n${step}. A venue tries to author a one-person predicate`)
    + dim("  (the proof hides the VALUES; a narrow enough RULE identifies the holder anyway)"));

  const roots = [
    { regimeHash: d.idRegime as `0x${string}`, ita: d.identityAnchor as `0x${string}` },
    { regimeHash: d.invRegime as `0x${string}`, ita: d.identityAnchor as `0x${string}` },
  ] as const;
  const none = { enabled: false, groupId: 0, attrIndex: 0, op: 0, value: 0n };
  const narrow = [
    { enabled: true, groupId: 0, attrIndex: 0, op: 1, value: 840n },  // resident US
    { enabled: true, groupId: 0, attrIndex: 2, op: 1, value: 442n },  // citizen LUX
    { enabled: true, groupId: 0, attrIndex: 4, op: 1, value: 1n },    // accredited
    { enabled: true, groupId: 0, attrIndex: 5, op: 1, value: 1n },    // qualified purchaser
    none, none,
  ];

  const author = wallet(DEPLOYER_PK);
  try {
    await author.writeContract({
      address: d.userPolicyRegistry as `0x${string}`, abi: abis.policy, functionName: "registerPolicy",
      args: ["fingerprint-policy", roots as any, d.ordb as `0x${string}`, narrow as any, 3600n],
    });
    console.log(red("   ✗ unexpected: a one-person predicate was accepted"));
  } catch (e: any) {
    const reason = /predicate not approved/.test(String(e?.message ?? e))
      ? "Policy: predicate not approved"
      : String(e?.message ?? e).split("\n")[0];
    console.log(green("   ✓ refused at registration: ") + dim(reason));
  }

  const v = await policy.read.latestVersion([d.policyId as `0x${string}`]);
  const [, , , approvedHash] = await policy.read.getPolicyVersion([d.policyId as `0x${string}`, v]);
  const name = await policy.read.predicateName([approvedHash]);
  console.log(dim(`   the venue's live predicate is a REVIEWED template: "${name}" ${short(approvedHash, 12)}`));
  console.log(dim("   cohort size cannot be computed on chain, so it is not guessed at, a curator approves"));
  console.log(dim("   clause sets, and a policy may carry nothing else.\n"));
}

/**
 * LAWFUL UNMASKING, whitepaper §5.4, and the answer to "so how do you ever catch anyone?"
 *
 * The Transaction Monitor flags a pseudonym and, by construction, holds NO identity: a pseudonym is
 * `H(H(H(did, salt), regime), contract)` and the salt is the holder's secret. So the Monitor can say
 * "this trader is sanctions-linked" and genuinely cannot say who they are.
 *
 * The Identity Keeper can HERE, because this demo publishes the salt (`GAP_DEMO_ALLOW_PUBLIC_SALT=1`,
 * custody model IK_CUSTODY_DEMO). That is worth saying plainly, because `person.ts` states the
 * opposite as the design: the salt "must never" reach the IK, and both statements are true of
 * different custody models:
 *
 *   IK_CUSTODY_DEMO (this demo)  the salt is a published constant, so the IK can recompute
 *   CLIENT_HELD     (the design) the holder keeps it, and the IK CANNOT recompute anything
 *
 * Under CLIENT_HELD this beat does not work, and nothing in this repository implements the route the
 * white paper gives for that case: §5.4 has the Identity Keeper REQUIRE its users to reveal the salt.
 * No compelled-reveal mechanism exists here. So read this act as "what the regulator's path looks
 * like when the keeper holds the salt", not as "the regulator always has a path".
 *
 * Given a pseudonym, a
 * regime and a contract, it recomputes the candidate pseudonym for each of ITS OWN onboarded holders
 * and looks for the match. That is a search over its own book, not a decryption, and not something
 * any other party can do.
 *
 * The protocol deliberately does not specify when an IK should comply; §5.4 is explicit that the
 * mechanism "is not part of GAP itself". What GAP guarantees is the SHAPE: privacy from the public
 * and from the Monitor, with exactly one accountable party able to resolve it. In the full stack this
 * is what a Master Security Holder File row is: a pseudonym joined to a KYC record by the party
 * entitled to join them.
 */
export async function cmdUnmask(pseudonym: bigint, scope: `0x${string}`, scopeLabel: string) {
  const { d } = contracts();
  const { USER, RECEIVER } = await import("./state");

  console.log(bold("\n── Lawful unmasking ──") + dim("  (whitepaper §5.4: the regulator's path)"));
  console.log(`   the Monitor flagged  ${red(short(toHex32(pseudonym), 14))}`);
  console.log(dim(`   scoped to ${scopeLabel}, and the Monitor cannot resolve it: it has no salt, so no`));
  console.log(dim("   candidate to compare against. That is the design, not a limitation of this demo."));

  // The IK holds the salt for every holder it onboarded, so it can recompute the candidate set.
  let found: { label: string; did: bigint } | undefined;
  let searched = 0;
  for (const id of [USER, RECEIVER]) {
    searched += 1;
    const candidate = await pseudonymFor(BigInt(d.idRegime), BigInt(scope), id);
    if (candidate === pseudonym) found = { label: id.label, did: id.did };
  }

  console.log(dim(`   the Identity Keeper recomputes ${searched} candidate pseudonyms from its own book…`));
  if (!found) {
    console.log(red("   ✗ no match: this pseudonym was not issued by this Keeper"));
    return undefined;
  }
  console.log(green(`   ✓ resolved to ${found.label}`) + dim(`  DID ${short(toHex32(found.did), 14)}`));
  console.log(dim("   One accountable party, holding a salt, over its own holders. Not a back door: no"));
  console.log(dim("   key opens this for anyone else, and the Keeper is the party already liable for the PII."));
  console.log("");
  return found;
}
