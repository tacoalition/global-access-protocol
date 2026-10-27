pragma circom 2.0.0;

// Client-custody well-formedness wrapper. The statement lives in lib/salt_binding.circom.
// The public list is the layout mirror: it must equal, in order, WF_CIRCUITS.saltBinding
// .publicSignals (packages/gap-sdk/src/wf-layout.ts) and the count pinned in
// scripts/v2/build-wf.sh. This is a circuit of its own — it shares nothing with the
// SessionManager's 19-slot layout and must never be conflated with it.

include "./lib/salt_binding.circom";

component main {public [saltCommitment]} = SaltBinding();
