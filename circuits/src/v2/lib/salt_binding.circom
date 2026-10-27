pragma circom 2.0.0;

// GAP v2 — client custody, statement 1 of 3: THE DEVICE HOLDS THE SALT BEHIND THIS COMMITMENT.
//
// PUBLIC (1)   saltCommitment
// PRIVATE      salt
//
// This is the enrolment statement. Before client custody, the IK could answer "does this subject's
// salt open their registered commitment?" by fetching the salt and rehashing it
// (`services/gap-ik-api/src/regulatory/salt-commitment.ts:assertSaltMatchesCommitment`). Under
// client custody there is no salt to fetch, and the same question has to be asked of the device.
//
// WHAT IT DOES NOT SAY, said out loud. This proof carries no nonce, no subject id and no channel
// binding, so it is REPLAYABLE: anyone who observes it can present it again for the same
// commitment. That is sound for what the statement means — "some party knows the preimage of this
// public value" stays true on replay — but it is NOT proof that the party presenting it is the
// holder. Freshness and identity must come from the authenticated submission channel around it;
// `packages/gap-sdk/src/wf-contract.ts` states that as a REQUIREMENT on the IK verifier rather
// than leaving it to be discovered.

include "./wf_gadgets.circom";

template SaltBinding() {
    signal input saltCommitment;   // public — the DID registry's immutable record
    signal input salt;             // private — never leaves the device

    component commitment = SaltCommitment();
    commitment.salt <== salt;
    saltCommitment === commitment.out;
}
