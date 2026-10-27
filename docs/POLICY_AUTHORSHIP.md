# Policy Authorship and the Anonymity Floor

Status: **BUILT.** The design in §4 shipped, `registerPolicy` requires `isAuthor[msg.sender]`
(`UserPolicyRegistry.sol:147`), `_storeVersion` requires `_approvedPredicate[v.clausesHash]` (`:192`),
and `approvePredicate` / `revokePredicate` / `setAuthor` exist as specified. The attribute widening it
gated also shipped: 8 attributes, `MAX_CLAUSES = 6`, and `attrIndex < 8` (`:201`).

**§2 below describes the code as it was BEFORE that**, and is kept as the record of what the design
was answering. Read it as history, not as a survey of the current state: a reviewer, reasonably,
read it as current and concluded a hole existed. Where §2 says `registerPolicy` is permissionless and
"nothing anywhere constrains how selective a clause set is," both are now false.

## 1. The leak

The proof hides attribute *values*. It cannot hide *that a wallet satisfied a policy*, because
that is what a session is for. Two things are public and always were, by design:

- the **policy**, clauses are stored in `UserPolicyRegistry` and `clausesHash` is public input 3
- the **session**, `SessionGranted(account, policyId, ...)` is an event keyed by the account

Compose them:

> Policy P (public): *US resident AND accredited AND qualified purchaser*
> Chain (public): *`0xABC` holds a valid session under P*
> ∴ `0xABC` is a US-resident accredited qualified purchaser.

Nothing leaked from the proof. **Satisfying a public requirement is itself the disclosure.**

This is normally survivable because the cohort is large, "US accredited QP" is O(10^5) people, and
that crowd, not the cryptography, is doing the privacy work. The hazard is that **every added clause
multiplies the narrowing**, and the venue chooses its own clauses. With citizenship in the
vocabulary a venue can author:

> *US resident AND accredited AND QP AND citizen of Luxembourg*

, plausibly a single-digit cohort worldwide. The system will then correctly and publicly announce
when that person shows up. Scale does not help: a bigger user base widens the crowd for *broad*
policies, but a narrow predicate carves out the same tiny cohort regardless of population. The
attack targets the predicate, not the population.

Why it matters for the regulatory story: the pitch is that a venue proves eligibility instead of
collecting and hoarding documents. A public registry of narrow policies plus public session grants
is the same haystack, rebuilt out of derived facts, and a venue can opt into it unilaterally.

## 2. The state this was written against (HISTORICAL, see the status line)

Read from the code, not assumed:

- `UserPolicyRegistry.registerPolicy` (`contracts/src/v2/UserPolicyRegistry.sol:67`) is
  **permissionless**, `external`, no access control, `policyId = keccak(msg.sender, name)`.
  The docstring at `:9` claims "TM-administered (P0-6)". **The code does not implement that.**
- `updatePolicy` (`:82`) checks only `m.owner == msg.sender`, so an author controls their own
  predicate forever, across versions.
- `_storeVersion` (`:96`) validates *shape* only: op ≤ GTE, attrIndex < 4, groupId < 2, value < P.
  **Nothing anywhere constrains how selective a clause set is.**
- A policy is inert until a filter references it: `TransactionFilterV2.setUserConfig` (`:57`) is
  `onlyAdmin`. So a stranger's policy gates nothing.

That last point bounds the threat. The vector is **not** an outsider registering a predicate: it is
the **legitimate venue admin** authoring a narrower one than the venue needs, and any public
observer reading the pair (policy, session grant). Permissionless registration is a separate
correctness gap (code contradicts its own docstring), not the privacy vector.

## 3. Two gaps, two fixes

| Gap | Today | Fix |
|---|---|---|
| **Authorship**, who may author a predicate | anyone | curator-gated author set |
| **Selectivity**, how narrow a predicate may be | unbounded | approved-template allowlist |

Selectivity is the one that actually closes the leak. Authorship alone does not: the venue admin is
already authorized and is the threat.

## 4. Design: gate on `clausesHash`

Cohort size **cannot be computed on-chain**: it depends on real-world population distributions the
chain has no access to. So do not attempt to measure it. Enumerate instead: a curator approves a set
of reviewed clause-sets, and venues may only select from them.

The enforcement point is already there. `clausesHash` is the canonical predicate commitment, is
computed on-chain in `_computeClausesHash` (`:130`), and is collision-resistant. So:

```solidity
// in _storeVersion, after v.clausesHash is computed:
require(_approvedPredicate[v.clausesHash], "Policy: predicate not approved");
```

One SLOAD. Because both `registerPolicy` and `updatePolicy` route through `_storeVersion`, this
covers the register-clean-then-narrow-by-update path with no extra code.

**The granularity is exactly right.** `clausesHash` commits to the clauses and nothing else, so a
venue keeps free choice of its operational config, `identityRoots`, `requiredORDB`,
`maxSessionValidity`, while losing the ability to invent a bespoke predicate. Privacy-relevant
fields are curated; operational fields are not.

**That sentence is wrong about `identityRoots`, and §6 now says so.** It is not an operational field:
the (ITA, regimeHash) pair fixes the candidate population exactly as directly as a clause does.

### Surface

```solidity
address public curator;                                   // governance / TM
mapping(bytes32 => bool)   private _approvedPredicate;    // clausesHash → approved
mapping(bytes32 => string) public  predicateName;         // clausesHash → "reg-d" (for UIs)
mapping(address => bool)   public  isAuthor;              // may call registerPolicy

function approvePredicate(PolicyClause[MAX_CLAUSES] calldata clauses, string calldata name)
    external onlyCurator returns (bytes32 predicateHash);
function revokePredicate(bytes32 predicateHash) external onlyCurator;
function setAuthor(address who, bool allowed) external onlyCurator;
```

`approvePredicate` takes the clauses (not a bare hash) so the approved predicate is legible in
calldata and in the event: a curator must never approve an opaque digest.

### Revocation semantics

`revokePredicate` must block *new* versions only. Existing sessions run to expiry, matching the
established `updatePolicy` rule (`:81`, P1-8). Do not retroactively invalidate: a live session whose
predicate was later retired is not a compliance failure, and tearing it down mid-flight would make
revocation a denial-of-service lever against holders.

### Seeding

The two zones in `packages/gap-cli/src/state.ts:220` (`general`, `reg-d`) are already exactly this, 
reviewed, deliberately broad clause-sets, used by convention. Approve them at deploy time and the
convention becomes enforcement with no behavioural change to the demo.

## 5. Why not the alternatives

- **Structural heuristics** (cap enabled clauses, ban `EQ` on high-cardinality attributes): narrowness
  is not structurally decidable. Two clauses at ~1/100 each already define a 1/10,000 cell without
  tripping any count-based rule. Gameable, and it gives false assurance.
- **Declared minimum cohort:** the declaration is unverifiable on-chain; it just relocates the
  curator's judgement into a number nobody can check.
- **Observed cohort floor** (refuse the k-th session until k accounts hold one): circular: the first
  k−1 grants are already public, which is the leak. Also a live DoS on the first holders.
- **Free-form authorship with disclosure warnings:** the observer, not the holder, is the adversary.
  Warning the holder changes nothing.

## 6. What this does *not* fix

**The floor curates the predicate, not the population, and this is the hole, not a residual.**
`_storeVersion` checks `identityRoots[i].ita != address(0)` and nothing more, and `SessionManager`
reads the regime root from whatever anchor the policy names. Deploying an Identity Trust Anchor is
permissionless, by design.

So the venue, which §2 identifies as *the* threat, does not need a narrow predicate at all. It
deploys its own anchor, adopts a regime, issues exactly one credential, points an **approved, broad**
predicate at that anchor, and reads the holder straight off `SessionGranted`. Every curated clause is
satisfied and the floor never fires. A reviewer found this by reading `_storeVersion` against
`_checkPolicyBindings`; it is not exploited here, but nothing stops it.

Closing it means curating accepted anchors the way `ContractRequirement.acceptedCTAs` already curates
certifiers for contract sessions: there is simply no user-session counterpart. That is a mechanism
change, not a wording one, and it is not made.

Until it is: **the anonymity floor raises the cost of a narrow predicate; it does not bound the
anonymity set.** Treat the two as different claims.

State these plainly rather than let the floor imply more safety than it delivers.

- **An approved-but-broad predicate still discloses its conjunction.** The floor raises the cohort
  from ~1 to ~10^5. It does not make session grants private.
- **Cross-venue linkage is untouched.** A wallet holding sessions under several policies is
  fingerprinted by the *set*, even when each policy is individually broad. This is the H2 concern in
  `SESSION_REVOCATION.md` (full stack, not in this repository); it needs its own treatment.
- **The curator is now a trusted party**, and a captured curator can approve a narrow predicate.
  Mitigation is procedural (public approval events, a timelock), not cryptographic.
- **Availability:** templates become a hard dependency. A curator outage blocks every new venue.
  Accept it for a reference implementation, but do not ship a production config without a timelocked
  fallback.

## 7. Cost

- Contract: ~60 lines added to `UserPolicyRegistry.sol`, one `require` in the write path, one SLOAD
  per policy write. No circuit change, `clausesHash` semantics are unchanged, so no ceremony, no
  re-mint, no verifier rebuild, and the 19-slot public layout is untouched.
- Deploy: `DeployV2.s.sol` seeds the two zone predicates and sets the curator.
- Tests: approve/revoke, unapproved predicate rejected on both `registerPolicy` and `updatePolicy`,
  revoked predicate blocks a new version while a live session survives to expiry, non-curator
  rejected, non-author rejected.
- Pre-production and testnet-only, so there is no migration path to preserve.

## 8. Demo consequence

This is showable, and it is the honest version of the privacy claim. The tour can state: *the venue
proves you are eligible without learning who you are, and it cannot invent a bespoke test narrow
enough to pick you out, because the eligibility rules come from a reviewed public set.* A scripted
failure (a venue attempting a one-person predicate and being rejected at registration) demonstrates
the floor in one transaction.
