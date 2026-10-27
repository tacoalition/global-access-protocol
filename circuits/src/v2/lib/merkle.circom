pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

template MerkleMembership(DEPTH) {
    signal input leaf;
    signal input siblings[DEPTH];
    signal input pathIndices[DEPTH];
    signal input root;

    signal hashes[DEPTH + 1];
    hashes[0] <== leaf;
    component h[DEPTH];
    component mux[DEPTH];
    for (var i = 0; i < DEPTH; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== siblings[i];
        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== pathIndices[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== mux[i].out[0];
        h[i].inputs[1] <== mux[i].out[1];
        hashes[i + 1] <== h[i].out;
    }
    root === hashes[DEPTH];
}

// Full ~254-bit field element split into two 127-bit limbs (strict/alias-safe),
// so field values can be order-compared with in-range LessThan gadgets.
template FieldLimbs() {
    signal input in;
    signal output hi;   // bits 127..253
    signal output lo;   // bits 0..126
    component bits = Num2Bits_strict();
    bits.in <== in;
    var loAcc = 0;
    var hiAcc = 0;
    var e = 1;
    for (var i = 0; i < 127; i++) {
        loAcc += bits.out[i] * e;
        hiAcc += bits.out[i + 127] * e;
        e *= 2;
    }
    lo <== loAcc;
    hi <== hiAcc;
}

// out = (a < b) lexicographically over (hi, lo) 127-bit limb pairs.
template LimbLt() {
    signal input aHi;
    signal input aLo;
    signal input bHi;
    signal input bLo;
    signal output out;
    component ltHi = LessThan(127);
    ltHi.in[0] <== aHi;
    ltHi.in[1] <== bHi;
    component eqHi = IsEqual();
    eqHi.in[0] <== aHi;
    eqHi.in[1] <== bHi;
    component ltLo = LessThan(127);
    ltLo.in[0] <== aLo;
    ltLo.in[1] <== bLo;
    out <== ltHi.out + eqHi.out * ltLo.out;
}

// Full-key NON-membership over an INDEXED Merkle tree (GAP-H1): the tree is a sorted
// linked list whose leaves are H2(key, nextKey) at allocation-ordered slots (genesis
// leaf H2(0,0) at slot 0; the tail's nextKey is 0). The prover shows a "low leaf"
// that is IN the tree and brackets the target: lowKey < key AND (nextKey == 0 OR
// key < nextKey). The ORDB contract maintains the sorted-list invariant (unique,
// non-zero, strictly ascending keys), so such a leaf exists iff `key` is absent —
// free path indices are safe because ANY tree leaf passing the range checks
// certifies absence. A flagged key's true predecessor has nextKey == key, and every
// other lower node's nextKey <= key, so no satisfying witness exists.
template IndexedNonMembership(DEPTH) {
    signal input key;              // full field element (pseudonym)
    signal input lowKey;
    signal input nextKey;
    signal input siblings[DEPTH];
    signal input pathIndices[DEPTH];
    signal input root;

    component leaf = Poseidon(2);
    leaf.inputs[0] <== lowKey;
    leaf.inputs[1] <== nextKey;
    component member = MerkleMembership(DEPTH);
    member.leaf <== leaf.out;
    for (var i = 0; i < DEPTH; i++) {
        member.siblings[i] <== siblings[i];
        member.pathIndices[i] <== pathIndices[i];
    }
    member.root <== root;

    component kL = FieldLimbs();
    kL.in <== key;
    component lowL = FieldLimbs();
    lowL.in <== lowKey;
    component nextL = FieldLimbs();
    nextL.in <== nextKey;

    // lowKey < key
    component lowLt = LimbLt();
    lowLt.aHi <== lowL.hi;
    lowLt.aLo <== lowL.lo;
    lowLt.bHi <== kL.hi;
    lowLt.bLo <== kL.lo;
    lowLt.out === 1;

    // nextKey == 0 (tail: nothing above lowKey)  OR  key < nextKey
    component nextGt = LimbLt();
    nextGt.aHi <== kL.hi;
    nextGt.aLo <== kL.lo;
    nextGt.bHi <== nextL.hi;
    nextGt.bLo <== nextL.lo;
    component nextZero = IsZero();
    nextZero.in <== nextKey;
    signal upperOk <== nextZero.out + nextGt.out - nextZero.out * nextGt.out;
    upperOk === 1;
}

// Fold-left Poseidon(2) chain matching GapLib/UserPolicyRegistry exactly.

