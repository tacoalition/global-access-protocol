pragma circom 2.0.0;

// GAP v2 — client custody, statement 3 of 3: BOTH ANCHORS CAME FROM THE ONE COMMITTED SALT.
//
// PUBLIC (6)   saltCommitment, did, regimeHash, gatedContract, masterPseudonym, pseudonym
// PRIVATE      salt
//
// ONE GADGET, TWO ANCHORS. `PseudonymAnchors` computes the session circuit's own fold chain
// (`gap_session.circom:163-172`) and exposes the value at BOTH the second and third step:
//
//   masterPseudonym = H2(H2(did, salt), regimeHash)                 <- pn2, contract-independent
//   pseudonym       = H2(masterPseudonym, gatedContract)            <- pn3, what the ORDB flags
//
// The IK therefore verifies, from one proof, that the name it will publish for this holder AT
// THIS VENUE and the name it uses to recognise this holder ACROSS venues are the same person's,
// and that that person is the one who registered `saltCommitment`. Two separate proofs of two
// separate derivations could not say the second half: nothing would tie their salts together.
//
// WHY THE COMMITMENT, NOT JUST THE DID, IS THE ANCHOR. `did` alone is public on-chain, so a fold
// over `did` and an unconstrained salt derives a pseudonym for a person the prover is not. The
// commitment is the link between the two anchors and the registry record, and it is checked here
// with the same `SaltCommitment` gadget the enrolment statement uses. This is the in-circuit form
// of `assertSaltMatchesCommitment`'s second arm — the check that "separates a WRONG salt from a
// merely well-formed one" (`services/gap-ik-api/src/regulatory/salt-commitment.ts`).
//
// `gatedContract` is a `DsiFundScopeAnchor`, never a token, in every deployment that has one; the
// circuit folds whatever scope it is given and the mandate decides which scopes may be asked for
// (`services/gap-ik-api/src/regulatory/pseudonym.ts`). One proof per scope, one shared master.

include "./wf_gadgets.circom";

template PseudonymWellFormed() {
    // ----- public -----
    signal input saltCommitment;
    signal input did;
    signal input regimeHash;
    signal input gatedContract;
    signal input masterPseudonym;
    signal input pseudonym;

    // ----- private -----
    signal input salt;

    component commitment = SaltCommitment();
    commitment.salt <== salt;
    saltCommitment === commitment.out;

    component anchors = PseudonymAnchors();
    anchors.did <== did;
    anchors.salt <== salt;
    anchors.regimeHash <== regimeHash;
    anchors.gatedContract <== gatedContract;
    masterPseudonym === anchors.master;
    pseudonym === anchors.perContract;
}
