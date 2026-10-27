# What is public on chain, and what is not

**F-11.** The next demo has to state this precisely, because the intuition ("it's zero-knowledge,
so nothing is visible") is wrong in a specific and checkable way, and a reviewer who forms the
wrong picture forms it about the wrong layer. Everything below was read off the contracts.

## The one-line version

**The DID is plaintext. The wallet↔DID link is what the proof protects, and until the spending
leaf was blinded, the registry gave that link away too.**

## Public to anyone, no keys

| What | Where | Notes |
|---|---|---|
| The DID itself | `DIDRegistryV2`: the mapping key, and `DIDRegistered(bytes32 indexed did, …)` (`:37`, emitted `:89`) | Plaintext, indexed. Enumerable from logs. |
| That a DID exists, and when | `DIDEntry.registeredAt`, `exists` (`:20-26`); `didCount` (`:35`) | |
| The salt COMMITMENT | `DIDEntry.privateSaltCommitment` = `H2(privateSalt, 0)`, **immutable** (`:21`) | A commitment, not the salt. Immutability is why a lost salt is a lost holder. |
| The spending-key ROOT | `DIDEntry.spendingKeyRoot` (`:22`), `SpendingKeyRootUpdated` (`:98`) | See the warning below. |
| Governance keys | `DIDEntry.governanceKeys`, up to 5 plaintext addresses (`:19`, `:23`) | Real addresses, in the clear. |
| That a credential exists for (regime, DID), and its expiry | `IdentityAnchor`, keyed by plaintext DID, `issueCredential(regimeHash, did, …)` (`:135-150`) | The credential CONTENT is a commitment; its existence and expiry are not. |
| Every flagged pseudonym | `OnchainRiskDatabase` `PseudonymFlagged(bytes32 indexed pseudonymHash, …)` (`:55`) | Cleartext, indexed, and **necessarily so**, see below. |
| Session existence, expiry, scope | `SessionManager` `_sessions[account][policyId]`, `SessionGranted` (`:77-83`) | Keyed by the ACCOUNT, in the clear. |
| The encrypted pseudonym | `SessionGranted` (`:210`), `getSession` (`:369-371`) | Ciphertext, BabyJubJub ECDH into XChaCha20-Poly1305, authenticated against the session's own context. Opens only to the monitor scalar, **which this demo publishes** (`gap-cli/src/monitor-key.ts`): the mechanism is the production one, the secret is not. |

## Protected

- **The wallet↔DID link.** This is the actual privacy claim. The circuit proves an address is a
  MEMBER of the DID's spending set without revealing the DID: `did` is a private witness and is not
  among the 19 public signals (`circuits/src/v2/session.circom:7-13`).
- **The salt.** Only its commitment is on chain, and only the holder (and, in today's IK-custody
  flow, the Identity Keeper) has the preimage.
- **Attribute values.** `attrs[0..7]` are folded into the credential leaf behind `attrsHash`; the
  chain holds a commitment, never a country or a sanctions bit.
- **The pseudonym behind a session, until that session is revoked.**
  `pseudonymCommitment = Poseidon(pseudonym, blindingR)` with a fresh per-grant `blindingR`, inside an
  XChaCha20-Poly1305 AEAD whose AAD is the session context. A keyless observer cannot match a flagged
  pseudonym to a `SessionGranted` envelope **while the session stands**.

  **`revokeSession` ends that, deliberately, for the session it closes.** It takes the pseudonym and
  its blinding factor as public calldata, next to the account, because the grounds are checked on
  chain: see the entry below.

## Revocation publishes the link it was protecting, for one session

This page said the opposite until an October 2026 review found it, and the correction matters more
than the defect: a document that tells a reader "this layer is sound; do not spend effort hardening
it" is worse than silence, because it instructs them not to look.

`SessionManager.revokeSession(account, policyId, pseudonym, blindingR)` puts all four values in public
calldata. So after a revocation, **any observer can permanently link that account to that pseudonym**,
and reopen the commitment in the account's own `SessionGranted` event.

**What that does NOT reach**, because both facts are load-bearing and both were checked:

- `blindingR` is sampled fresh per session (`gap-sdk/src/input-builder.ts:261`), so the disclosure
  reopens exactly one commitment. Earlier and later sessions of the same holder are untouched.
- The pseudonym is per-contract, `pn3 = H2(pn2, gatedContract)`, so the link is to that holder's
  activity **on one venue**, not across the system. A different venue's pseudonym for the same holder
  stays unlinkable.

**What it does reach:** for that venue, the flag becomes attributable to a wallet. The flag set is
public by design (below), so pseudonym → wallet is the last step that was missing.

**Why it is this way.** Any grounds that an outside party can CHECK must name the account and the
pseudonym in the same public call: that is what checkable means. The alternative is the state this
replaced, where a Transaction Monitor could close any session for any reason with no on-chain record
of why. That was worse, and the trade was made knowingly; it was the failure to write it down that was
the mistake. If the privacy of a revoked session matters more than the auditability of the revocation,
the honest fix is to move the grounds off chain again and accept an unconstrained TM, not to pretend
this call is private.

## A pseudonym is scoped to regime 0, and that is a per-policy choice

`pseudonym = H2(H2(H2(did, salt), regimeHash0), gatedContract)`: the regime in the fold is
`identityRoots[0].regimeHash`, which each policy picks freely. `SessionManager` pins `pub[8]` to
whatever the policy names and nothing constrains it.

**So two policies at the SAME gated contract with different `identityRoots[0]` give one holder two
different, unlinkable pseudonyms there, and a flag against one does not stop sessions under the
other.** Every policy the deploy creates happens to use the same identity regime, so the demo never
shows it; nothing enforces it.

Whether that is a feature or a hole depends on what you want. It is a feature if the two regimes are
genuinely different populations that a monitor should track separately. It is a hole if a venue
reaches for it to give a flagged holder a fresh identity at the same venue. A deployment that cares
should either fix `identityRoots[0]` across the policies a single ORDB monitors, or accept that its
flag scope is per-(policy, regime) rather than per-holder.

Found by review; recorded here because it appears in no other document and a deployer copying this
tree would not discover it until a flag failed to bite.

## Two things to say out loud, because they are the ones that get mis-stated

**1. The spending-key root WAS a preimage of the holder's wallets, and is not any more.** With an
unblinded leaf, a deterministic address-derived slot and a deterministic zero-chain, a one-wallet
holder's published root was `f(address)`, computable by anyone in eight hashes. That handed out
`did ↔ wallet` for free and defeated address rotation. The leaf is blinded now
(the spending-set privacy notes (full stack)); the roots registered before that change remain preimages
for the wallets under them.

**2. The flagged-pseudonym set is public ON PURPOSE and cannot be otherwise here.** The circuit
proves ORDB non-membership by having a clean holder bracket their key in a **sorted plaintext**
list (`gap_session.circom`), and the witness is served permissionlessly. The flagged set must be
readable for any honest holder to prove they are not in it. The DSI Regulatory Model's footnote
that the pseudonym is *"encrypted so only the Transaction Monitor can see it"* is not achievable on
this construction, only a re-randomizable accumulator or an oblivious lookup would get there, and
both are circuit changes. **This is a documented departure, not a defect to patch.**

## The correction to make if the earlier framing comes up

An earlier description had credentials sitting *under* the spending root. They do not: credentials
live in per-regime `IdentityAnchor` trees keyed by the plaintext DID, and the spending root is a
separate tree of the holder's addresses hanging off the DID entry. The membership-proof intuition
was right; the placement was not.
