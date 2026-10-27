pragma circom 2.0.0;

// Client-custody well-formedness wrapper. The statement lives in lib/pseudonym_wf.circom.
// The public list is the layout mirror: it must equal, in order, WF_CIRCUITS
// .pseudonymWellFormed.publicSignals (packages/gap-sdk/src/wf-layout.ts) and the count pinned in
// scripts/v2/build-wf.sh. Two anchors — the per-contract pseudonym and the master it is built on
// — under one salt commitment.

include "./lib/pseudonym_wf.circom";

component main {public [
    saltCommitment, did, regimeHash, gatedContract, masterPseudonym, pseudonym
]} = PseudonymWellFormed();
