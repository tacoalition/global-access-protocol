pragma circom 2.0.0;

// GAP v2 — client-custody WELL-FORMEDNESS gadgets.
//
// WHY THIS FILE EXISTS. Once the holder's device holds the private salt, the Identity Keeper can
// no longer recompute a salt commitment, a credential leaf or a pseudonym for itself: every check
// it used to make by rebuilding the value (`services/gap-ik-api/src/regulatory/salt-commitment.ts`
// `assertSaltMatchesCommitment`, `packages/gap-identity-keeper-v2/src/credential-builder.ts`
// `computeCredentialLeaf`) requires the salt as an argument. These gadgets are those same three
// folds, arranged so the DEVICE proves them and the IK checks a proof instead of a preimage.
//
// EVERY FOLD HERE IS `H2Chain`, THE TEMPLATE THE SESSION CIRCUIT ALREADY USES
// (`./policy.circom`). There is deliberately not one `Poseidon(2)` component in this file: a
// second transcription of a fold is the defect class this repo keeps finding, and a
// well-formedness check that hashed differently from the session circuit would admit exactly the
// commitments the session circuit can never open — the failure it exists to prevent.
//
// `H2Chain(2)([a, b])` is one Poseidon(2) of `(a, b)`, so the chain is the primitive as well as
// the fold; nothing is spent on the reuse.

include "./policy.circom";

/**
 * keccak256("GAP_ATTR_CRED_V3") mod p — the credential-leaf domain tag.
 *
 * MIRRORS (change one, change all; `docs/gap-v2/ATTRIBUTE_ENCODING.md` carries the full table):
 *   contracts/src/v2/libraries/GapLib.sol            credTag()
 *   circuits/src/v2/lib/gap_session.circom:57        CRED_TAG
 *   packages/gap-identity-keeper-v2/src/field.ts     CRED_TAG
 *   packages/gap-sdk/src/types.ts                    CRED_TAG
 *   circuits/scripts/v2/prove_session.js:27          CRED_TAG
 *
 * `scripts/v2/build-wf.sh` refuses to build unless this literal is byte-identical to
 * `gap_session.circom`'s, so the mirror is checked rather than merely documented.
 */
function CRED_TAG_V3() {
    return 7398619034839472060957547841361825911550539606183619483712186628328937676175;
}

/**
 * `H2(salt, 0)` — the value `DIDRegistryV2` stores as `privateSaltCommitment`, immutably, at
 * registration. Mirror of `gap_session.circom:62-64`.
 *
 * The trailing zero is not padding: it is what makes the commitment a fixed, single-arity fold
 * every lane can reproduce, and it is why the IK-side `saltCommitment()` helper takes one salt.
 */
template SaltCommitment() {
    signal input salt;
    signal output out;

    component h = H2Chain(2);
    h.in[0] <== salt;
    h.in[1] <== 0;
    out <== h.out;
}

/**
 * The 8-field `GAP_ATTR_CRED_V3` credential leaf. Mirror of `gap_session.circom:97-105` (and of
 * `:117-125`, which is the same fold for the second regime).
 *
 *   leaf = H2Chain(TAG, ita, regimeHash, did, attrsHash, salt, ikId, expiresAt)
 *
 * The attributes enter ONLY through `attrsHash` — they are never separate leaf fields
 * (`docs/gap-v2/ATTRIBUTE_ENCODING.md` § How attributes reach the chain).
 */
template CredentialLeaf() {
    signal input ita;
    signal input regimeHash;
    signal input did;
    signal input attrsHash;
    signal input salt;
    signal input ikId;
    signal input expiresAt;
    signal output out;

    component leaf = H2Chain(8);
    leaf.in[0] <== CRED_TAG_V3();
    leaf.in[1] <== ita;
    leaf.in[2] <== regimeHash;
    leaf.in[3] <== did;
    leaf.in[4] <== attrsHash;
    leaf.in[5] <== salt;
    leaf.in[6] <== ikId;
    leaf.in[7] <== expiresAt;
    out <== leaf.out;
}

/**
 * BOTH pseudonym anchors, from one salt, in one gadget. Mirror of `gap_session.circom:163-172`:
 *
 *   pn1 = H2(did, salt)
 *   pn2 = H2(pn1, regimeHash)     <- `master`      : the regime-scoped, contract-INDEPENDENT name
 *   pn3 = H2(pn2, gatedContract)  <- `perContract` : the name a venue's ORDB actually flags
 *
 * `pn1`/`pn2` are the prefix `pn3` is built on, so computing both costs three Poseidons — exactly
 * what the session circuit spends — rather than two separate chains. That the master anchor is
 * genuinely a PREFIX is the whole reason it can be published beside the per-contract one: the IK
 * learns that two names it is shown share a salt without learning the salt, and a holder who
 * later appears at a second venue is recognisable as the same person to the party that already
 * holds their master anchor, and to nobody else.
 *
 * The per-security scope decision (`docs/gap-v2/ATTRIBUTE_ENCODING.md` § Per-security scope) is
 * what makes this necessary: one holder carries a different `perContract` per security, so
 * without a shared `master` the IK could not tell a second registration from a second person.
 */
template PseudonymAnchors() {
    signal input did;
    signal input salt;
    signal input regimeHash;
    signal input gatedContract;
    signal output master;
    signal output perContract;

    component m = H2Chain(3);
    m.in[0] <== did;
    m.in[1] <== salt;
    m.in[2] <== regimeHash;
    master <== m.out;

    component c = H2Chain(2);
    c.in[0] <== master;
    c.in[1] <== gatedContract;
    perContract <== c.out;
}
