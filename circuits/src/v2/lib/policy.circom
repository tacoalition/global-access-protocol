pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux3.circom";

template H2Chain(N) {
    signal input in[N];
    signal output out;
    component h[N - 1];
    signal acc[N];
    acc[0] <== in[0];
    for (var i = 0; i < N - 1; i++) {
        h[i] = Poseidon(2);
        h[i].inputs[0] <== acc[i];
        h[i].inputs[1] <== in[i + 1];
        acc[i + 1] <== h[i].out;
    }
    out <== acc[N - 1];
}

// The per-regime attribute fold: FOUR attributes per regime under GAP_ATTR_CRED_V3.
// ONE transcription, shared by the session circuit (gap_session.circom) and the client-custody
// well-formedness circuit (cred_wf.circom). A divergence between those two would admit exactly the
// credentials the session circuit can never open — the failure wf_gadgets.circom exists to prevent.
// Note this is Poseidon(4), NOT H2Chain(4): they are different functions.
template AttrsHash() {
    signal input attrs[4];
    signal output out;
    component h = Poseidon(4);
    for (var i = 0; i < 4; i++) h.inputs[i] <== attrs[i];
    out <== h.out;
}

// One DNF clause evaluation over attrs[8]. Returns opResult (1 = pass).
template ClauseEval() {
    signal input attrs[8];
    signal input enabled;    // bool
    signal input groupId;    // 0..1
    signal input attrIndex;  // 0..7
    signal input op;         // 0..6 (NONE,EQ,NEQ,LT,LTE,GT,GTE)
    signal input value;      // < 2^64
    signal output meta;      // enabled | groupId<<8 | attrIndex<<16 | op<<24
    signal output active0;   // enabled AND groupId==0
    signal output active1;   // enabled AND groupId==1
    signal output pass;      // op result (only meaningful when enabled)

    // range/shape constraints
    enabled * (enabled - 1) === 0;
    groupId * (groupId - 1) === 0;
    component aiBits = Num2Bits(3);
    aiBits.in <== attrIndex;
    component opBits = Num2Bits(3);
    opBits.in <== op;
    // enabled clauses must not use op == NONE
    component opIsNone = IsZero();
    opIsNone.in <== op;
    enabled * opIsNone.out === 0;

    meta <== enabled + groupId * 256 + attrIndex * 65536 + op * 16777216;

    // select attribute (8-to-1 mux by attrIndex bits)
    component sel = Mux3();
    sel.c[0] <== attrs[0];
    sel.c[1] <== attrs[1];
    sel.c[2] <== attrs[2];
    sel.c[3] <== attrs[3];
    sel.c[4] <== attrs[4];
    sel.c[5] <== attrs[5];
    sel.c[6] <== attrs[6];
    sel.c[7] <== attrs[7];
    sel.s[0] <== aiBits.out[0];
    sel.s[1] <== aiBits.out[1];
    sel.s[2] <== aiBits.out[2];
    signal a <== sel.out;

    // comparator range: value < 2^64 (contract-enforced too); attr < 2^64 enforced in main
    component vBits = Num2Bits(64);
    vBits.in <== value;

    component eqc = IsEqual();
    eqc.in[0] <== a;
    eqc.in[1] <== value;
    component ltc = LessThan(64);
    ltc.in[0] <== a;
    ltc.in[1] <== value;
    signal eq <== eqc.out;
    signal lt <== ltc.out;
    signal lte <== lt + eq - lt * eq;

    // op indicator selection: result = sum_k [op==k] * res_k
    component opIs[7];
    for (var k = 0; k < 7; k++) {
        opIs[k] = IsEqual();
        opIs[k].in[0] <== op;
        opIs[k].in[1] <== k;
    }
    signal r1 <== opIs[1].out * eq;          // EQ
    signal r2 <== opIs[2].out * (1 - eq);    // NEQ
    signal r3 <== opIs[3].out * lt;          // LT
    signal r4 <== opIs[4].out * lte;         // LTE
    signal r5 <== opIs[5].out * (1 - lte);   // GT
    signal r6 <== opIs[6].out * (1 - lt);    // GTE
    pass <== r1 + r2 + r3 + r4 + r5 + r6;

    // group membership indicators
    active0 <== enabled * (1 - groupId);
    active1 <== enabled * groupId;
}

