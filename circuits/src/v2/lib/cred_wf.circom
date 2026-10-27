pragma circom 2.0.0;

// GAP v2 — client custody, statement 2 of 3: THIS LEAF IS THE LEAF FOR WHAT THE IK ATTESTED.
//
// PUBLIC (8)   leaf, saltCommitment, ita, regimeHash, did, attrsHash, ikId, expiresAt
// PRIVATE      salt, attrs[4]
//
// THE SPLIT, AND WHY IT IS THIS ONE. The 8-field leaf is
// `H2Chain(TAG, ita, regimeHash, did, attrsHash, salt, ikId, expiresAt)`
// (`gap_session.circom:97-105`). TAG is a compile-time constant, so seven fields are left. Six of
// them — ita, regimeHash, did, attrsHash, ikId, expiresAt — are things the ISSUER decided: they
// are in its own issuance record before the device is handed anything, so making them public
// costs no privacy the IK does not already have and buys the only thing that matters, which is
// that the IK compares them against its record field by field rather than trusting a digest it
// cannot open. The seventh, the salt, is the one field the IK must NOT learn; it appears as
// `saltCommitment` instead.
//
// WHY `saltCommitment` IS PUBLIC HERE AT ALL. Without it the statement degrades to "the device
// knows SOME salt producing this leaf", which any salt satisfies. A leaf built under a salt other
// than the DID's registered one is not merely wrong, it is UNUSABLE: the session circuit folds one
// `privateSalt` into both the DID leaf and the credential leaf (`gap_session.circom:63`, `:103`),
// so the holder could never open it again. Binding the commitment turns that from a bricked
// credential discovered at first session into a refusal before anything is anchored — which is
// the entire point of checking well-formedness BEFORE the write.
//
// WHY THE ATTRIBUTES STAY PRIVATE. `docs/gap-v2/ATTRIBUTE_ENCODING.md` is emphatic that the
// attributes are private witnesses and appear in no public layout; residency and accreditation in
// the clear, beside a DID, in an artifact an IK may retain, would be a new place for them to leak.
// The IK already holds the values it attested, so it recomputes `attrsHash` with the SAME shared
// hasher it built the credential with (`credential-builder.ts:72`) and compares one field. The
// binding is identical and the public signals stay hash-only.
//
// Requiring the preimage rather than accepting the hash alone is not free ceremony either: it
// certifies that the device actually HOLDS the attribute values, which it will need as private
// witnesses of every session proof. A device that has the leaf but not its attributes cannot
// transact, and this is where that is caught.
//
// The `Num2Bits(64)` bound is the same one `gap_session.circom:208-213` applies. It is what makes
// the 64-bit clause comparators sound (`policy.circom:60-62`), and here it certifies the bound
// WITHOUT revealing the values.

include "./wf_gadgets.circom";

template CredentialWellFormed() {
    // ----- public: the leaf, and every field the issuer decided -----
    signal input leaf;
    signal input saltCommitment;
    signal input ita;
    signal input regimeHash;
    signal input did;
    signal input attrsHash;
    signal input ikId;
    signal input expiresAt;

    // ----- private: the two things the IK must not learn -----
    signal input salt;
    signal input attrs[4];

    // 1. the salt is the one the DID registry pinned
    component commitment = SaltCommitment();
    commitment.salt <== salt;
    saltCommitment === commitment.out;

    // 2. attrsHash opens to four uint64 attributes the device actually holds
    component attributes = AttrsHash();
    for (var a = 0; a < 4; a++) attributes.attrs[a] <== attrs[a];
    attrsHash === attributes.out;

    component bound[4];
    for (var i = 0; i < 4; i++) {
        bound[i] = Num2Bits(64);
        bound[i].in <== attrs[i];
    }

    // 3. the leaf is that fold over exactly those publics and that salt
    component credential = CredentialLeaf();
    credential.ita <== ita;
    credential.regimeHash <== regimeHash;
    credential.did <== did;
    credential.attrsHash <== attrsHash;
    credential.salt <== salt;
    credential.ikId <== ikId;
    credential.expiresAt <== expiresAt;
    leaf === credential.out;
}
