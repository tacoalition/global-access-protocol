# What this implements, measured against the white paper

Section numbers below refer to **The Global Access Protocol (A draft white paper)**, Digital
Securities Initiative. The coalition publishes it at [tacoalition.org](https://www.tacoalition.org/global-access-protocol/lite-paper); if the published
overview is shorter than the draft, this map is what the numbers mean:

| § | heading | § | heading |
|---|---|---|---|
| 1 | Problem Statement | 5 | Transaction Monitoring |
| 2 | Summary of GAP | 5.1 / 5.2 | Objectives / Pseudonyms and the Sybil problem |
| 3 | Users and Attributes | 5.3 / 5.4 | Onchain Risk Databases / Regulatory Reporting |
| 3.1 / 3.2 | Objectives / Digital Identities | 6 | Transaction Filters |
| 3.3 | Attribute Regimes and Attribute Credentials | 6.1 / 6.2 | Objectives / User Policies |
| 3.4 | Identity Trust Anchors and Identity Keepers | 6.3 / 6.4 | Sessions / Transaction Filter |
| 4 | Smart Contracts and Classifications | 7 | An Example |
| 4.1 / 4.2 | Objectives / Classification Regimes | 8 | Conclusion |
| 4.3 | Contract Trust Anchors and Contract Certifiers | App. I / II / III | Glossary / Privacy Vaults / Sybil Resistant Credentials |


Read against *The Global Access Protocol (A draft white paper)*, section by section, checking the code
rather than the design documents. The headline: **the protocol core is implemented and faithful.** What
is missing is mostly deployment surface, plus two mechanisms the paper names and this does not build.

## Implemented, and faithful to the paper

| § | Mechanism | Where |
|---|---|---|
| 3.2 | DID registry: singleton, DID documents, mutable governance key, mutable Spending Key Commitment, **immutable** Private Salt commitment, DID Root as a sparse Merkle tree, registration fee | `DIDRegistryV2.sol` |
| 3.3 | Attribute Regime Registry: singleton, open to any party, fee against abuse, unique identifier per regime | `RegimeRegistry.sol` |
| 3.3 | Attribute Credential as a salted hash, **with the metadata field** Appendix III depends on | `IdentityAnchor.sol` |
| 3.4 | Identity Trust Anchor contract: per-regime trees, Attribute Regime Root as a ZK public input, Identity Keeper whitelist, IK ejection | `IdentityAnchor.sol` |
| 3.4 | **The Sybil rule**: one Attribute Credential per DID per regime per anchor | `require(existing.issuedAt == 0 \|\| existing.revoked)` |
| 4.2 | Classification Regime: Contract Classes, human-readable name and binary code | `RegimeRegistry.sol`, `ClassificationAnchor.sol` |
| 4.3 | Contract Trust Anchor contract, Contract Certifier whitelist, Contract Sessions in the Session Manager | `ClassificationAnchor.sol`, `SessionManager.sol` |
| 5.2 | `Pseudonym = hash(DID, Private Salt, Attribute Regime, contract address)`, as the pn1/pn2/pn3 fold | `gap_session.circom` |
| 5.2 | Encrypted Pseudonym carrying a reference to the Identity Keeper | session `encryptedPseudonym` |
| 5.3 | Onchain Risk Database per Transaction Monitor, risk flags as a fixed-width string, Risk Root | `OnchainRiskDatabase.sol`, note `ORDBFactory` EXISTS but is used by nothing: the deploy scripts construct ORDBs directly, so the paper's factory is present in form and not in use |
| 5.4 | Regulatory reporting: the Monitor refers the regulator to the Identity Keeper, **but only under IK-held custody; see the gap below** | `gap-cli disclosure`/`unmask` |
| 6.2 | User Policy as a predicate over attributes, Policy ID, on-chain registry, administrator who can update, **but see the gap below: it does not range over risk flags** | `UserPolicyRegistry.sol` |
| 6.3 | User Session proving all five claims the paper lists, with an expiry | `session.circom`, `SessionManager.sol` |
| 6.4 | Transaction Filter keyed on function **and argument position**, `check` for the sender, `checkRecipient` for the counterparty | `TransactionFilterV2.sol` |
| 6.4 | Contract-session spec (classes, regimes, accepted anchors) and user-session spec (policies, regimes, anchors, ORDBs) | `ContractRequirement`, `setUserConfig` |
| 7 | **The worked example**: a swap across three contracts, each with its own Transaction Filter, Monitor and Onchain Risk Database | `make dex-up` |

Section 7 is worth calling out. The paper's closing example is a DEX swap between two tokenized
securities where every contract carries its own filter and its own monitor, and that is literally what
`make dex-up` deploys and `make demo` exercises, down to the pool holding its security through a
Contract Session from a "Compliant DEX" Classification Credential.

## Divergences, each deliberate and documented

**The DID is supplied, not derived from the transaction hash** (§3.2). The paper removes the choice to
prevent griefing. Ours is issued off-chain by the Identity Keeper, and registration is commit-reveal so
the slot cannot be front-run.

The vector that forces commit-reveal is front-running, not squatting. Squatting by guessing is not
feasible: the DID is a keyed PRF of the subject id, so an attacker cannot predict the value the
Keeper will derive. Front-running is feasible, and worse than denial. A pending `registerDID`
reveals `did` and `privateSaltCommitment` in the clear, and `require(callerIsKey)` only checks that
the caller appears in the `governanceKeys` array *they themselves supplied*. So an attacker copies
the victim's `did` and commitment, substitutes their own address as the governance key, and
registers first: the victim's transaction reverts with `DID: exists`, the attacker holds governance
over the victim's DID including `updateSpendingKeyRoot`, and the victim cannot fall back to a second
DID, because provisioning refuses a subject that derives a different one.

`commitRegistration` therefore takes a digest over every field *and the registrant*, and
`registerDID` requires that commitment to have been made in a strictly earlier block. The DID stays
secret until the reveal, so a front-runner would need a commitment from before they could have known
it. An EIP-712 signature from a registered Keeper would also work and is the more obvious answer; it
was rejected on cost, because `DIDRegistryV2` holds no reference to the Keeper registry.

**~~Flagged pseudonyms are public, not encrypted to the Monitor~~: this was never a divergence from
THIS paper, and listing it as one was an error.** GAP §5.3 specifies *"a key value store mapping hashed
pseudonyms to a Risk Flag"*: a public store, which is exactly what is built. The encryption footnote
belongs to the **DSI Regulatory Model**, a different document, which `ON_CHAIN_DISCLOSURE.md` attributes
correctly.

The argument still stands where it applies: a clean holder proves NON-membership by bracketing their
pseudonym between adjacent entries of a sorted list, so the list must be readable by the person making
the proof, and encrypting it to the Monitor alone removes the only way the innocent can clear
themselves. It just is not a departure from the GAP white paper. On §5.3, the implementation conforms.

**A Monitor can close a session** (§6.3). The paper states as a property that no party can dynamically
invalidate a User Session. Ours can, but only on proof that the pseudonym is flagged AND reopens that
session's own commitment.

## Specified in the paper, not built here

Ranked by how much the absence costs.

**1. The ZK proof does not prove the encryption is well formed** (§5.2). The paper: *"a ZK proof is
required to prove that an Encrypted Pseudonym is generated correctly, since the virtual machine cannot
distinguish between a genuine ciphertext and random bytes."* Ours proves the pseudonym commitment and
leaves the ciphertext to a Transaction Monitor attestation, which gates the session until the Monitor
confirms it decrypts. The property the paper wants is obtained: a malformed ciphertext never yields a
usable session, but by a trusted step rather than by the proof, and the holder waits on it. The
blocker is the ceremony ceiling, not the technique: binding the key to the Monitor's actual public key
needs a BabyJubJub scalar multiplication at roughly 2,500–4,000 constraints against **1,193 spare**
under the 2^16 ptau.

**2. No version interface for mutable contracts** (§4.3). The paper: *"GAP defines an interface that
allows smart contracts to list versions of mutable smart contracts. The Contract Sessions then list the
version number, forcing developers to start a new Contract Session for each update."* Not built. We use
a certifier assertion (`codeIsImmutable`), a venue requirement, and a bounded `maxAge` instead.

Worth being precise about why, because `CONTRACT_UPGRADES.md` argues the chain cannot detect an
upgrade and that remains true *against an adversary*: a self-reported version is exactly as forgeable
as the upgrade it describes, so a malicious developer simply does not bump it. What the paper's
interface would genuinely buy is the honest case: a developer who upgrades and forgets, plus an
audit trail. That is real value we are not capturing.

**3. User Policies do not range over risk flags** (§6.2), and this is the gap that was missing from
this list until a review found it. The paper's worked example is *"reject users that are Syrians **AND
have a structuring Risk Flag**"*: a predicate over attributes **and** flags. Ours is a DNF over
`attrs[8]` only: `grep -i "risk\|flag" UserPolicyRegistry.sol` returns nothing, and the contract's own
docstring says "fixed-size DNF predicate over attributes." Risk enters as a single hard-wired check, 
total non-membership in one ORDB, so a policy can say "not flagged at all" and cannot say "flagged
THIS way, combined with that attribute."

That is a real expressiveness gap against a named example, and it is the most substantive
paper-versus-code difference in the tree. Closing it means risk flags as clause operands in-circuit,
which costs constraints against a budget with 1,193 spare.

**4. The referral route names only credential 0's issuer** (§5.4). `ikRefCommitment` binds the issuer
proven in credential leaf 0, not the credential the policy's DNF actually selected. Since `attrs[4..7]`
are attested by a different authority than `attrs[0..3]`, a regulator following the referral can reach
the identity keeper and never the one that attested suitability. Tracked in-circuit as GAP-H5; the demo
hides it by issuing both credentials under the same keeper id.

**5. The §5.4 referral route is not reachable under the custody model the code prescribes.** The
paper's mechanism is a COMPELLED REVEAL: "an Identity Keeper can require its users to reveal to them
their Private Salt", and nothing here implements one. The demo's unmasking act works because
`GAP_DEMO_ALLOW_PUBLIC_SALT=1` publishes the salt; under `CLIENT_HELD`, which `person.ts` describes as
the design ("the salt must never" reach the IK), the keeper cannot recompute candidates at all.

So §5.4 is demonstrated, not implemented: the act shows what the regulator's path looks like when the
keeper holds the salt, and the path for when it does not is absent. Found by review; it had been
listed as implemented and faithful with no caveat.

**6. Certifier delegation** (§4.3), *"GAP contains the functionality that allows a Contract Certifier
to delegate its ability to issue credentials."* Absent. A feature, not a hole.

**7. Factories for three of the four deployable contracts** (§3.4, §4.3, §6.4). The paper specifies a
factory for Identity Trust Anchor contracts, for Contract Trust Anchor contracts, and for Transaction
Filters. Only the Onchain Risk Database has one. Deployment works without them, but "any organization
can declare itself a Trust Anchor and join" is a weaker claim when joining means deploying by hand
rather than through a protocol entry point.

**8. Identity Keeper identity is anchor-scoped** (footnote 11): the paper wants a singleton registry so
one Keeper is recognisable as the same entity across every anchor it operates under. Ours derives
`ikId` from the anchor address, so it is not.

**9. No anchor forking** (§3.4), *"if a trust anchor becomes corrupted or ineffective, another
organization can simply fork it."* Named as the anti-ossification valve. Not implemented, and it needs
a credential-migration story that does not silently re-attest claims the new anchor never verified.

**10. Privacy Vaults** (Appendix II) and **Private Set Membership** (Appendix III.ii). Neither built. The
paper itself places PSM outside the protocol; Privacy Vaults are offered as a novel addition rather
than a requirement.

## The short version

Everything the protocol needs in order to *work* is here, and the paper's own closing example runs as a
demo. The gaps are: one cryptographic shortcut taken under a ceremony ceiling (the encryption proof),
one mechanism replaced with a different approach (contract versioning), and a set of ecosystem features
, factories, delegation, portable Keeper identity, forking: that matter for the paper's
decentralization story rather than for whether a Regulated Zone functions.
