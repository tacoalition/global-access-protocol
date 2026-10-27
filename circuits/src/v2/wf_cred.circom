pragma circom 2.0.0;

// Client-custody well-formedness wrapper. The statement lives in lib/cred_wf.circom.
// The public list is the layout mirror: it must equal, in order, WF_CIRCUITS
// .credentialWellFormed.publicSignals (packages/gap-sdk/src/wf-layout.ts) and the count pinned
// in scripts/v2/build-wf.sh. Eight publics for an eight-field leaf, with the salt replaced by
// its commitment at slot 1 — attrs stay private and reach the layout only as attrsHash.

include "./lib/cred_wf.circom";

component main {public [
    leaf, saltCommitment, ita, regimeHash, did, attrsHash, ikId, expiresAt
]} = CredentialWellFormed();
