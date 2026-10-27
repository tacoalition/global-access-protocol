# Attribute encoding

Why this exists: `attrs[0..7]` is the entire vocabulary a fund can gate on. Eight uint64s decide
who may hold a security, and each one is a claim some authority made about a person. This
document pins what each index MEANS, who is allowed to say it, how it reaches a credential leaf,
how a fund tests it, and what it costs to add a ninth. Every claim below cites the code that
enforces it; when the code and this file disagree, the code is right and this file is a defect.

The attributes are **private witnesses**. They appear nowhere in the 19 public inputs
(`circuits/src/v2/session.circom:7-14`, `contracts/src/v2/SessionManager.sol:27-33`): the chain
learns only that a predicate over them passed, as `clausesHash`.

## The vocabulary

| Index | Meaning | Regime | Authority | Derived by |
|---|---|---|---|---|
| `attrs[0]` | ISO 3166-1 **numeric** residency country, where the person LIVES | `standard-identity` v1.0.0 | the KYC provider's signed decision | `attribute-derivation.ts` |
| `attrs[1]` | sanctions flag, **always 0 on an issued credential** | `standard-identity` v1.0.0 | the KYC provider's signed decision | `attribute-derivation.ts` |
| `attrs[2]` | ISO 3166-1 **numeric** citizenship country: what the person is a NATIONAL of | `standard-identity` v1.0.0 | the KYC provider's signed decision | `attribute-derivation.ts` |
| `attrs[3]` | reserved, always 0 | `standard-identity` v1.0.0 |, |, |
| `attrs[4]` | accredited investor | `investor-status` v1.0.0 | the **fund IK's** reviewed suitability determination | `suitability-attestation.ts` |
| `attrs[5]` | qualified purchaser | `investor-status` v1.0.0 | the **fund IK's** reviewed suitability determination | `suitability-attestation.ts` |
| `attrs[6]` | **evidence tier 1..5** behind the accredited determination | `investor-status` v1.0.0 | the **fund IK's** reviewed determination | `suitability-attestation.ts` |
| `attrs[7]` | reserved, always 0 | `investor-status` v1.0.0 |, |, |

`attrs[3]` and `attrs[7]` stay reserved so a future claim need not repeat this migration, see
"Extending the vocabulary" for what filling one costs. `attrs[6]` was one, and is now spent.

The two regimes are named at `contracts/script/integrations/DeployJoinedBaseFundLocal.s.sol:52-53`
and hashed by `GapLib.regimeHash(regimeId, major, minor, patch)`
(`contracts/src/v2/libraries/GapLib.sol:39-44`). Regime 0 carries `attrs[0..3]`, regime 1 carries
`attrs[4..7]`: the split is structural, not a convention: they are two different credential
leaves, proven against two different Merkle roots, and the wiring is fixed at
`circuits/src/v2/lib/gap_session.circom:36`.

### `attrs[0]` and `attrs[2]`, residency and citizenship, deliberately separate

**They are different claims and they are different indices.** Conflating them is wrong in both
directions: a single `residency == 840` slot admits a US citizen living abroad and rejects a US
resident travelling on a foreign passport, and a jurisdictional programme may key on either. The
conflation was real rather than hypothetical: the IK has always derived this slot from the
provider's `residencyCountryAlpha3`, while `packages/gap-cli/src/state.ts` and both zone templates
described the same slot as "citizenship". Splitting it is what makes the two testable apart.

Only ONE country fits per index. A dual national cannot be represented here: a packed encoding of
two codes would break `EQ` clauses (`citizenship == 840` fails against a packed `840|276`), and a
"multiple" sentinel is exactly the value `country-table.ts` refuses to mint for an unknown
jurisdiction, for the same reason. Screening a prohibited-nationality list AT ISSUANCE: the
fail-closed shape `attrs[1]` already uses, is the natural answer and is **not implemented**.


`deriveIdentityAttributes` resolves the provider's alpha-3 through a **closed, reviewed** table
(`packages/gap-identity-keeper-v2/src/country-table.ts`). There is deliberately no
unknown-jurisdiction sentinel (`country-table.ts:11-13`): an alpha-3 outside the set is a refusal
(`country-table.ts:68-77`), never a numeric that merely fails to equal 840. A sentinel would be a
value a `{attrIndex:0, EQ, …}` clause could not distinguish from a real country it was not written
to admit.

The table is versioned. `COUNTRY_TABLE_REVISION` (`country-table.ts:15`) is signed into the
provider's decision at slot 13 of its 19-slot envelope
(`provider-attestation.ts:29`, `:130`), `countryTableDigest()` (`country-table.ts:59-63`) is pinned
in IK config, and both the envelope check (`provider-attestation.ts:192`) and the derivation
(`attribute-derivation.ts:92-94`) refuse a mismatch. That is what stops a provider signing "GBR"
under a table where GBR meant something else.

### `attrs[1]`, sanctions, as a refusal rather than an encoding

**A credential is never issued carrying `attrs[1] = 1`.** `deriveIdentityAttributes` returns the
literal `[country, 0n]` (`attribute-derivation.ts:107`) and refuses every non-clean case first: a
review answer that is not GREEN (`:95-97`), a decision carrying a reject type (`:98-100`), an
unresolved screening hit (`:101-103`). The gate on the writing side re-checks it
(the Identity Keeper service, not in this repository).

The reasoning is quoted verbatim from `attribute-derivation.ts:79-87`, because it is the whole
argument:

> Encoding "sanctioned" into a live credential and relying on a fund's `{attrIndex:1, EQ, 0}`
> clause to block it is policy-dependent, not fail-closed: clauses are individually enabled, so a
> fund that does not test attrIndex 1 would admit the holder. A post-issuance HIT is handled by
> the existing revoke path.

That revoke path is `IdentityAnchor.revokeCredential` (`contracts/src/v2/IdentityAnchor.sol:177`),
which zeroes the leaf so the membership proof fails. The IK's own state machine escalates the
same way in-flight: `requiresImmediateHold` (`attribute-derivation.ts:67-70`) holds on SUSPENDED,
REVOKED, REJECTED, RETRY_REQUIRED and RECONCILE_REQUIRED, and any divergence from the adapter's
view resolves to RECONCILE_REQUIRED, which blocks (`:39-65`).

So `attrs[1]` in a valid credential is always 0, and a fund's `sanctioned == 0` clause is
defence in depth over an invariant already held at issuance, not the thing holding the line.

### `attrs[4..5]`, suitability, and its three separations from KYC

A KYC vendor has no view of income, net worth or holdings, and does not bear the Reg D / 3(c)(7)
determination. The fund IK makes it itself, against evidence it reviewed, and signs a
`DSI_FUND_IK_SUITABILITY_ATTESTATION_V1` envelope
(`packages/gap-identity-keeper-v2/src/suitability-attestation.ts:52`). The payload is a canonical
**13-slot** positional decode (`:53`, slot map at `:117-127`):

```
0  profile tag    4  subjectDid    8  basis                 12  expiresAt
1  authority      5  revision      9  accredited   (attrs[2])
2  environment    6  reviewerId   10  qualifiedPurchaser (attrs[3])
3  fundIkId       7  evidenceDigest 11 reviewedAt
```

Three independent separations keep a KYC GREEN from ever being sufficient to mint accredited/QP
(`suitability-attestation.ts:27-39`): a **different profile tag**, so a provider envelope cannot
even parse here; a **different authority slot** (`"fund-ik"`, never `"kyc-provider"`, `:131`); and a
**different pinned key set**, which `assertSuitabilityKeysAreDistinct`
(`packages/gap-identity-keeper-v2/src/suitability-gate.ts:73-105`) refuses to let overlap the KYC
provider's pinned keys, by keyId **and** by key material.

Two payload rules are normative. **QP dominates accreditation**: a qualified-purchaser
determination without accreditation is not a state that exists and is rejected (`:151-157`).
**Freshness is 90 days** (`:60`): the SEC's own Rule 506(c) verification safe harbor, so a
determination older than that has to be re-reviewed, not re-signed; `verifySuitabilityAttestation`
refuses a stale one (`:217-219`), an expired one (`:214-216`), and one reviewed in the future
(`:211-213`). The credential the CLI lane then mints is capped at 7 days and additionally clamped
to the attestation's own `expiresAt` (`packages/gap-cli/src/mint-guard.ts:56`, `:204`).

There is **one verifier for two lanes**: the CLI demo lane (`packages/gap-cli/src/mint-guard.ts`)
and the IK service (the Identity Keeper service, not in this repository) import the same
module. The service previously minted `[1n, 1n]` from a constant; that is the defect this
arrangement exists to prevent, and a second copy of the verifier would reintroduce it. Where a
determination comes FROM was later widened to a union (env artifact → persisted artifact → the
fund-suitability desk), but the verdict is unchanged and re-verified rather than re-fetched
(the Identity Keeper service, not in this repository).

## How attributes reach the chain: the credential leaf

Both regimes' attributes live inside an **8-field** Poseidon chain under the domain tag
`keccak256("GAP_ATTR_CRED_V3") mod P`:

```
leaf = H2Chain(TAG, ita, regimeHash, did, attrsHash, privateSalt, ikId, expiresAt)
attrsHash = Poseidon(4)(attrs[4k .. 4k+3])          # exactly four attributes per regime
```

`attrsHash` is a **genuine `Poseidon(4)`, not `H2Chain(4)`**, different functions that disagree, so
the wrong one produces a leaf the circuit cannot reopen. The fold lives ONCE as `AttrsHash()` in
`policy.circom`, shared by the session and well-formedness circuits (`gap_crypto.js` `h4`, IK
`hash4`), and was verified against circomlibjs before anything was built on it.

The attributes enter only through `attrsHash`: they are never separate leaf fields. The leaf is
computed offchain by the IK (it contains private data) and re-derived in-circuit, and the anchor
stores only the commitment (`contracts/src/v2/IdentityAnchor.sol:14`, `:135`).

**Mirrors, change one, change all** (this is the invariant list for anything in this document):

| Mirror | Where |
|---|---|
| tag, canonical | `contracts/src/v2/libraries/GapLib.sol` `credTag()` |
| tag + leaf, in-circuit | `circuits/src/v2/lib/gap_session.circom` `CRED_TAG` |
| tag, well-formedness circuit | `circuits/src/v2/lib/wf_gadgets.circom` `CRED_TAG_V3()` |
| the `attrsHash` fold itself | `circuits/src/v2/lib/policy.circom` `AttrsHash()`; ONE transcription, used by both the session and well-formedness circuits |
| leaf, IK writer | `packages/gap-identity-keeper-v2/src/credential-builder.ts` (tag at `field.ts`, fold via `hash4`) |
| leaf, SDK prover | `packages/gap-sdk/src/prover.ts` (tag at `types.ts`, fold via `crypto.h4`) |
| leaf, client-custody witness | `packages/gap-sdk/src/wf-witness.ts` (fold via `crypto.h4`) |
| leaf, circuit prover | `circuits/scripts/v2/prove_session.js` (fold via `gc.h4`) |
| the fold, offchain | `circuits/scripts/v2/gap_crypto.js` `h4`, **not** `chain`, which is a different function |
| tag, CLI lane | `packages/gap-cli/src/state.ts` |

`build-wf.sh` refuses to build unless the tag matches both circuits, and `invariant-parity.test.mjs` (the full stack calls its equivalent `invariant-parity.test.mjs` (the full stack calls its equivalent `depth-parity.test.mjs`, not in this repository)) asserts it is one value everywhere, checked, not merely documented.

**Bounds.** Every attribute is a uint64. The derivation refuses anything wider
(`attribute-derivation.ts:108-112`), the leaf builder refuses it again
(`credential-builder.ts:70`), and the circuit range-constrains all eight with `Num2Bits(64)`
(`gap_session.circom:208-213`). The bound is not cosmetic: the clause comparators are 64-bit
(`circuits/src/v2/lib/policy.circom:60-62`), and an out-of-range attribute makes `LessThan`
unsound: a holder could satisfy a `GT` clause they fail.

The version suffix in the tag is itself the versioning mechanism. V2 folded `expiresAt` into the
leaf, domain-separating the 7-field V1 leaves from the 8-field V2 ones. **V3 widens `attrsHash` from
`Poseidon(2)` to `Poseidon(4)`**, four attributes per regime instead of two, so the bump separates
V2 leaves from V3 ones (`GapLib.sol:18-24`). The leaf's FIELD LIST is unchanged; what changed is what
`attrsHash` commits to, and that is enough to require a new tag.

## The clause side: how a fund gates on attributes

A policy is a fixed-size DNF predicate over the eight indices. Each clause is
`{enabled, groupId, attrIndex, op, value}` (`contracts/src/v2/UserPolicyRegistry.sol:25-31`), with
`MAX_CLAUSES = 6`, two groups, `ClauseOp ∈ {NONE, EQ, NEQ, LT, LTE, GT, GTE}`.
Clauses in a group AND; groups OR, mirrored in-circuit at `gap_session.circom`.
The registry validates the shape on write, `attrIndex < 8`, `groupId < 2`, `op <= GTE`,
`value < P`, and the circuit re-derives it, with `attrIndex` range-constrained to
**three bits** and an enabled clause forbidden from using `op == NONE`
(`policy.circom:39-46`).

**Six, not eight, and that is a measured ceiling rather than a preference.** Each clause costs
+1,230 constraints. At production tree depths the circuit measures 64,255 with six clauses and
**66,715 with eight, over the 2^16 ptau's 65,536**. Seven fits by 51 constraints, which is no room
for any later change; the full stack's hardening notes carry the measured table.

**Authorship is curated.** A policy may only carry a clause set a curator has approved
(`UserPolicyRegistry.approvePredicate`). Clauses are public and session grants are public, so a
sufficiently narrow predicate would identify its holder from `SessionGranted` alone, which is
precisely what a wider vocabulary makes expressible. See `POLICY_AUTHORSHIP.md`.

The binding is `clausesHash`: `acc = 0`, then per clause `acc = H2(H2(acc, meta), value)` with
`meta = enabled | groupId<<8 | attrIndex<<16 | op<<24`. Computed on-chain once per policy version
(`UserPolicyRegistry.sol:126-142`), recomputed in-circuit from private clause witnesses
(`gap_session.circom:215-231`), exposed as public input `[3]`, and pinned by the Session Manager
against the policy it is granting under (`SessionManager.sol:334`). A holder therefore cannot
prove against a predicate the venue did not publish.

**Zones** are the reviewed clause templates. `packages/gap-cli/src/state.ts:220-241`:

| Zone | Clauses (all group 0, all `EQ`) |
|---|---|
| `general` | `attrs[1] == 0` (not sanctioned), `attrs[0] == 840` (resident US) |
| `reg-d` | the same two, plus `attrs[4] == 1` (accredited) |
| `dex-*` | the same first two, scoped to the DEX's own ORDB (`DeployDexV2.s.sol`) |

`attrs[5]` (QP) has no zone yet, it is carried, attested and provable, and awaits a 3(c)(7) zone.

**`attrs[6]` is the one attribute gated with a THRESHOLD.** The DEX policy carries
`{attrIndex: 6, op: GTE, value: 3}`, so a holder proves their determination rests on evidence at or
above "documented balance sheet" **without revealing which basis it was**. Until this landed every
shipped clause was an `EQ` and the `LT/LTE/GT/GTE` family was dead code. The tier is ATTESTED, not
derived: the ordering is a policy decision pinned in `EVIDENCE_TIER_BY_BASIS` with a revision, which
the IK checks the attested value against, so a desk cannot promote its own evidence class.
Note what `reg-d` shows: the accredited leaf is the key to that zone, which is why an unattested
`[1n, 1n]` there was a real hole and not a cosmetic one.

**`attrs[2]` (citizenship) has no zone either, and that is the live gap.** It is derived, attested
and provable, but no shipped template tests it, so the simulator's `us-resident-ir-citizen` profile
(resident USA, national of IRN, screening CLEAR) passes `general` today. Splitting the index is what
makes that case *expressible*; writing the clause is a separate, reviewed decision.

**Per-security scope.** Since the full stack's local deployment moved to one scope anchor per
security (full stack, not in this repository), the anchor is folded into the
pseudonym, in-circuit as `gatedContract` (`gap_session.circom:162-172`) and IK-side as
`fundScopeAnchor` (the Identity Keeper service, not in this repository). The attributes do
not change per security; the **name they are proven under** does. The consequences are stated
rather than hidden in the full stack's per-security scope test (not in this repository):
a behavioural flag isolates to one security, and the cost is a session proof per security and N
flags for a sanction that must stop a holder everywhere.

## Extending the vocabulary

**Who is authoritative, per index.** Indices 0–1 belong to the KYC provider, reaching the leaf
only through the IK's identity regime, `assertIssuableIdentityDecision` returns the provider's
own derived pair so no caller is ever in a position to supply its own
(`identity-credential-gate.ts:50-84`), and `mintGatedIdentityCredential` gates and writes in one
step, never one without the other (`:109-131`). Indices 2–3 belong to the fund IK / suitability
desk, and only through `verifySuitabilityAttestation`. A new index must name its authority the
same way: a signed envelope, a pinned key set disjoint from every other authority's, and a gate
in the shared `gap-identity-keeper-v2` package so every lane imports one verifier.

**What is additive, and cheap** (no circuit change, no ceremony):

- **A new value in an existing index's vocabulary**, e.g. a country. Bump
  `COUNTRY_TABLE_REVISION` and the pinned digest, and have the provider re-sign under it
  (`country-table.ts:15`, `provider-attestation.ts:130`, `:192`).
- **A new clause over an existing index.** `updatePolicy` mints a new version and a new
  `clausesHash`; existing sessions run to expiry rather than being retroactively invalidated
  (`UserPolicyRegistry.sol:81-94`).
- **A new zone**, which is just a reviewed clause template plus its deployment wiring.

**There are now TWO reserved slots per regime** (`attrs[3]`, `attrs[6..7]`). Filling one is cheap:
it already has a place in `attrsHash` and in the 3-bit `attrIndex`, so it costs an issuer change and
a clause: **no new tag, no ceremony, no re-mint**. Use a reserved slot before widening again.

**What the V2 → V3 widening actually cost**, recorded because the estimate was wrong in the place
that mattered. This section used to be a forecast; it is now a measurement.

| | local | joined local | joined production |
|---|---|---|---|
| V2 (4 attrs / 4 clauses) | 55,877 | 57,957 | 61,077 |
| V3 (8 attrs / 6 clauses) | **59,143** | **61,135** | **64,255** |

Marginal cost is **+718 for the attributes** (flat) and **+1,230 per clause**. The trap: 8 attributes
with *8* clauses measures **66,715** at production depth, over the 2^16 ptau's 65,536. A hand estimate
said it fit. Compile before committing to a shape.

Public inputs stayed at **19**, so the 19-slot layout and its six mirrors were untouched, attributes
are private witnesses, which is why widening them is affordable at all.

What a further widening (a NINTH attribute, past the reserved slots) would cost:

1. **Circuit**, widen `attrs`, `AttrsHash()`'s arity, the `Num2Bits(64)` loop, and `ClauseEval`'s
   `Num2Bits(3)` → 4 bits with `Mux3` → `Mux4`. The ptau ceiling is the binding limit, not a round
   number, and at production depth there are only ~1,193 constraints left.
2. **A new domain tag**, `GAP_ATTR_CRED_V4`, mirrored into every row of the mirror table above.
   The versioning rule: **a new value or a new clause is additive under the current tag; any change
   to the leaf's field list or to `attrsHash` is a new tag.**
3. **Contracts**, `GapLib.credTag`, the `attrIndex < 8` bound, `evaluate(uint256[8])`.
4. **Ceremony and redeployment**, recompile, new phase-2 close, regenerate the verifier, redeploy
   it AND everything holding it immutably, `sessionManager` and the verifier have no setter. Old leaves are under
   the old tag and stop verifying, so **every credential is re-minted**; that migration, not the
   circuit edit, is the real cost.
5. **Issuers**: the provider envelope is a signed POSITIONAL payload, so a new attested field
   means a new profile string (V2→V3 moved `DSI_PROVIDER_IDENTITY_ATTESTATION_V1` to `V2` and 19
   slots to 20). Bump the profile with the shape, or an old payload decodes against wrong positions.
6. **Consumers**, `ZONES` (`state.ts`), every deploy script's policy template, the provers' witness
   builders, and **the bundled browser worker**, which enforces the old wire width until rebuilt.
7. **Docs**: this file.

Before any of that: check whether the claim is really a new attribute, or a reserved slot, or a new
*value* of an existing index, or a new clause. Three of those four are a config change.
