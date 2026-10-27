pragma circom 2.0.0;

include "./merkle.circom";
include "./policy.circom";

template GapSession(DID_DEPTH, SK_DEPTH, CRED_DEPTH, RDB_DEPTH, MAX_CLAUSES) {
    // ===== PUBLIC INPUTS (order = SessionManager layout) =====
    signal input account;
    signal input chainId;
    signal input sessionManager;
    signal input clausesHash;
    signal input validUntil;
    signal input accountNonce;
    signal input didRoot;
    signal input ita0;
    signal input regimeHash0;
    signal input credRoot0;
    signal input ita1;
    signal input regimeHash1;
    signal input credRoot1;
    signal input ordbId;
    signal input riskRoot;
    signal input gatedContract;
    signal input pseudonymCommitment;   // Poseidon(pseudonym, blindingR) — TM opens after decrypt
    signal input ikRefCommitment;       // Poseidon(ita0, ikId0) — referral route bound to the credential
    signal input monitorKeyId;          // which TM key the wallet encrypted to (SM pins to ORDB)

    // ===== PRIVATE WITNESSES =====
    signal input did;
    signal input privateSalt;
    signal input ikBlind;          // blinds ikRefCommitment; the TM gets it in the ciphertext
    signal input spendingKeyRoot;
    signal input didSiblings[DID_DEPTH];
    signal input didPathIndices[DID_DEPTH];
    signal input skSiblings[SK_DEPTH];
    signal input skPathIndices[SK_DEPTH];
    signal input attrs[8];                    // regime0: attrs[0..3], regime1: attrs[4..7]
    signal input ikId0;
    signal input ikId1;
    signal input cred0ExpiresAt;              // folded into leaf 0 (0 = no expiry) — GAP-H2
    signal input cred1ExpiresAt;              // folded into leaf 1 (0 = no expiry) — GAP-H2
    signal input cred0Siblings[CRED_DEPTH];
    signal input cred0PathIndices[CRED_DEPTH];
    signal input cred1Siblings[CRED_DEPTH];
    signal input cred1PathIndices[CRED_DEPTH];
    signal input rdbLowKey;                   // ORDB low leaf: greatest flagged key < pseudonym
    signal input rdbNextKey;                  // its successor (0 = tail)
    signal input rdbSiblings[RDB_DEPTH];
    signal input rdbPathIndices[RDB_DEPTH];   // the low leaf's allocation slot bits (free; membership)
    signal input blindingR;                   // commitment blinding (also encrypted to the TM)
    // DNF clauses (bound to clausesHash)
    signal input clEnabled[MAX_CLAUSES];
    signal input clGroupId[MAX_CLAUSES];
    signal input clAttrIndex[MAX_CLAUSES];
    signal input clOp[MAX_CLAUSES];
    signal input clValue[MAX_CLAUSES];

    var CRED_TAG = 7398619034839472060957547841361825911550539606183619483712186628328937676175;
    // ^ keccak256("GAP_ATTR_CRED_V3") mod p  (== GapLib.credTag()). V2 folded expiresAt into the
    //   leaf (GAP-H2); V3 widens attrsHash from Poseidon(2) to Poseidon(4) — four attributes per
    //   regime instead of two — so the bump domain-separates V2 leaves from V3 ones.

    // keccak256("GAP_SPENDING_BLIND_V2") mod p — the spending-leaf blinding tag, same derivation.
    // MIRRORS: packages/gap-identity-keeper-v2/src/field.ts, packages/gap-sdk/src/types.ts,
    // circuits/scripts/v2/prove_session.js — bound by scripts/platform/depth-parity.test.mjs.
    var SPENDING_BLIND_TAG = 20739668207314188630064942382150002554459284316356860011996029219836196127177;

    // ---- 1. DID document membership: leaf = H2(H2(did, saltCommit), spendingKeyRoot) ----
    component saltCommit = Poseidon(2);
    saltCommit.inputs[0] <== privateSalt;
    saltCommit.inputs[1] <== 0;
    component didInner = Poseidon(2);
    didInner.inputs[0] <== did;
    didInner.inputs[1] <== saltCommit.out;
    component didLeaf = Poseidon(2);
    didLeaf.inputs[0] <== didInner.out;
    didLeaf.inputs[1] <== spendingKeyRoot;
    component didMember = MerkleMembership(DID_DEPTH);
    didMember.leaf <== didLeaf.out;
    for (var i = 0; i < DID_DEPTH; i++) {
        didMember.siblings[i] <== didSiblings[i];
        didMember.pathIndices[i] <== didPathIndices[i];
    }
    didMember.root <== didRoot;

    // ---- 2. Spending-key membership: H2(account, spendingBlind) ∈ spendingKeyRoot ----
    //
    // THE SECOND INPUT USED TO BE ZERO, AND THAT MADE THE PUBLISHED ROOT A KEYLESS PREIMAGE OF THE
    // HOLDER'S WALLETS. `DIDRegistryV2` publishes `spendingKeyRoot` in an indexed event and a free
    // view; with an unblinded leaf, a deterministic address-derived slot and a deterministic
    // zero-chain for empty subtrees, a one-wallet holder's root was f(address) — eight Poseidon
    // hashes anyone could evaluate over a candidate set the chain hands out for free. Matching
    // that against published roots yielded did↔wallet permanently, and it defeated address
    // rotation, because the rotation set is itself published under one DID.
    //
    // The blind is derived from `privateSalt`, ALREADY a private input here (it is folded into
    // both credential leaves below), so this adds no witness field, no distribution problem and no
    // new custody question — one Poseidon. docs/gap-v2/SPENDING_SET_PRIVACY.md.
    component spendingBlind = Poseidon(2);
    spendingBlind.inputs[0] <== privateSalt;
    spendingBlind.inputs[1] <== SPENDING_BLIND_TAG;
    component skLeaf = Poseidon(2);
    skLeaf.inputs[0] <== account;
    skLeaf.inputs[1] <== spendingBlind.out;
    component skMember = MerkleMembership(SK_DEPTH);
    skMember.leaf <== skLeaf.out;
    for (var i = 0; i < SK_DEPTH; i++) {
        skMember.siblings[i] <== skSiblings[i];
        skMember.pathIndices[i] <== skPathIndices[i];
    }
    skMember.root <== spendingKeyRoot;

    // ---- 3. Credential membership ×2: leaf = fold(TAG, ita, regime, did, attrsHash, salt, ikId, expiresAt) ----
    // expiresAt is FOLDED INTO THE LEAF (GAP-H2), so the prover cannot present a different expiry
    // than the IK issued; §3b below constrains the session against it.
    component attrsHash0 = AttrsHash();
    for (var a0 = 0; a0 < 4; a0++) attrsHash0.attrs[a0] <== attrs[0 + a0];
    component leaf0 = H2Chain(8);
    leaf0.in[0] <== CRED_TAG;
    leaf0.in[1] <== ita0;
    leaf0.in[2] <== regimeHash0;
    leaf0.in[3] <== did;
    leaf0.in[4] <== attrsHash0.out;
    leaf0.in[5] <== privateSalt;
    leaf0.in[6] <== ikId0;
    leaf0.in[7] <== cred0ExpiresAt;
    component cred0Member = MerkleMembership(CRED_DEPTH);
    cred0Member.leaf <== leaf0.out;
    for (var i = 0; i < CRED_DEPTH; i++) {
        cred0Member.siblings[i] <== cred0Siblings[i];
        cred0Member.pathIndices[i] <== cred0PathIndices[i];
    }
    cred0Member.root <== credRoot0;

    component attrsHash1 = AttrsHash();
    for (var a1 = 0; a1 < 4; a1++) attrsHash1.attrs[a1] <== attrs[4 + a1];
    component leaf1 = H2Chain(8);
    leaf1.in[0] <== CRED_TAG;
    leaf1.in[1] <== ita1;
    leaf1.in[2] <== regimeHash1;
    leaf1.in[3] <== did;
    leaf1.in[4] <== attrsHash1.out;
    leaf1.in[5] <== privateSalt;
    leaf1.in[6] <== ikId1;
    leaf1.in[7] <== cred1ExpiresAt;
    component cred1Member = MerkleMembership(CRED_DEPTH);
    cred1Member.leaf <== leaf1.out;
    for (var i = 0; i < CRED_DEPTH; i++) {
        cred1Member.siblings[i] <== cred1Siblings[i];
        cred1Member.pathIndices[i] <== cred1PathIndices[i];
    }
    cred1Member.root <== credRoot1;

    // ---- 3b. Credential expiry (GAP-H2): the session may not outlive either credential ----
    // Per credential: expiresAt == 0 ("no expiry") OR validUntil <= expiresAt. The SM separately
    // requires validUntil > block.timestamp, so an expired credential (expiresAt < now) can never
    // mint a fresh session. Range checks make the 64-bit comparator sound; validUntil is already
    // capped to uint64 by the SM's calldata binding (checked here again, defense in depth).
    component vuBits = Num2Bits(64);
    vuBits.in <== validUntil;
    component exp0Bits = Num2Bits(64);
    exp0Bits.in <== cred0ExpiresAt;
    component exp1Bits = Num2Bits(64);
    exp1Bits.in <== cred1ExpiresAt;

    component exp0None = IsZero();
    exp0None.in <== cred0ExpiresAt;
    component exp0Cmp = LessEqThan(64);
    exp0Cmp.in[0] <== validUntil;
    exp0Cmp.in[1] <== cred0ExpiresAt;
    signal exp0Ok <== exp0None.out + exp0Cmp.out - exp0None.out * exp0Cmp.out;
    exp0Ok === 1;

    component exp1None = IsZero();
    exp1None.in <== cred1ExpiresAt;
    component exp1Cmp = LessEqThan(64);
    exp1Cmp.in[0] <== validUntil;
    exp1Cmp.in[1] <== cred1ExpiresAt;
    signal exp1Ok <== exp1None.out + exp1Cmp.out - exp1None.out * exp1Cmp.out;
    exp1Ok === 1;

    // ---- 4. Pseudonym = H2(H2(H2(did, salt), regimeHash0), gatedContract) ----
    component pn1 = Poseidon(2);
    pn1.inputs[0] <== did;
    pn1.inputs[1] <== privateSalt;
    component pn2 = Poseidon(2);
    pn2.inputs[0] <== pn1.out;
    pn2.inputs[1] <== regimeHash0;
    component pn3 = Poseidon(2);
    pn3.inputs[0] <== pn2.out;
    pn3.inputs[1] <== gatedContract;
    signal pseudonym <== pn3.out;

    // ---- 5. ORDB full-key NON-membership: low leaf brackets the pseudonym (GAP-H1) ----
    component nonIncl = IndexedNonMembership(RDB_DEPTH);
    nonIncl.key <== pseudonym;
    nonIncl.lowKey <== rdbLowKey;
    nonIncl.nextKey <== rdbNextKey;
    for (var i = 0; i < RDB_DEPTH; i++) {
        nonIncl.siblings[i] <== rdbSiblings[i];
        nonIncl.pathIndices[i] <== rdbPathIndices[i];
    }
    nonIncl.root <== riskRoot;

    // ---- 6. Encrypted-pseudonym binding (option-3 hybrid; ECDH done off-circuit) ----
    // pseudonymCommitment = Poseidon(pseudonym, blindingR). The wallet ECIES-encrypts
    // {pseudonym, blindingR, IK_ref} to the TM's key OFF-circuit; the TM decrypts, recomputes
    // this commitment, and PRE-ATTESTS the session on-chain (GAP-H3, route a) — the session is
    // unusable until SessionManager.attestSession. Full in-circuit ECIES (session_full.circom,
    // ~65k constraints) remains the documented route-(b) alternative for deployments that cannot
    // tolerate TM-liveness trust.
    component pc = Poseidon(2);
    pc.inputs[0] <== pseudonym;
    pc.inputs[1] <== blindingR;
    pseudonymCommitment === pc.out;

    // ikRefCommitment = Poseidon(ita0, ikId0, ikBlind): the referral route is bound IN-circuit to
    // the SAME issuer proven in credential leaf 0 (adversarial finding #5). The TM confirms the
    // decrypted IK_ref hashes to this — so a spoofed route fails.
    //
    // BLINDED, AND IT WAS NOT. This was Poseidon(ita0, ikId0) over two PUBLIC values: `ita0` is a
    // contract address and `ikId0` is emitted in the clear by `IKRegistered`. So the commitment
    // inverted by table lookup — anyone could enumerate every (anchor, keeper) pair, hash them, and
    // read the Identity Keeper straight off a `SessionGranted` event. Verified before fixing: on a
    // live chain, 6 of 6 sessions resolved to the keeper by name, with no keys.
    //
    // That breaks the paper's §5.2 directly, which says a Transaction Monitor discovers the Identity
    // Keeper "without revealing this information to the general public" — and it compounds, because
    // `CredentialIssued` already makes keeper -> DIDs enumerable, so an unblinded reference narrows a
    // session's candidate DID set from every DID to the ones that keeper issued.
    //
    // `ikBlind` is sampled fresh per session and travels in the ciphertext beside `blindingR`. A
    // SEPARATE factor rather than reusing `blindingR`: recovering one should not open the other, and
    // these two commitments protect different things.
    //
    // STILL OPEN (GAP-H5): this binds the issuer of CREDENTIAL 0 only, not the credential the DNF
    // actually selected. A reviewer noticed the commit that blinded this also deleted the note, which
    // left the tree with no record of a live limitation — the blinding changed how the value is
    // hidden, not what it names.
    //
    // It matters for the referral route, which is the regulator's only path to PII (white paper
    // §5.4). ATTRIBUTE_ENCODING.md records that attrs[4..7] are attested by a DIFFERENT authority, so
    // a referral built from this commitment can name the identity keeper and can never name the one
    // that attested suitability. The demo does not show it because it issues both credentials under
    // the same ikId.
    component irc = Poseidon(3);
    irc.inputs[0] <== ita0;
    irc.inputs[1] <== ikId0;
    irc.inputs[2] <== ikBlind;
    ikRefCommitment === irc.out;

    // ---- 7. DNF predicate: fold clauses → clausesHash; evaluate → must pass ----
    // attribute range constraint (comparator soundness): attrs < 2^64
    component attrBits[8];
    for (var i = 0; i < 8; i++) {
        attrBits[i] = Num2Bits(64);
        attrBits[i].in <== attrs[i];
    }

    component clauses[MAX_CLAUSES];
    signal foldIn[MAX_CLAUSES * 2 + 1];
    foldIn[0] <== 0;
    for (var i = 0; i < MAX_CLAUSES; i++) {
        clauses[i] = ClauseEval();
        for (var j = 0; j < 8; j++) clauses[i].attrs[j] <== attrs[j];
        clauses[i].enabled <== clEnabled[i];
        clauses[i].groupId <== clGroupId[i];
        clauses[i].attrIndex <== clAttrIndex[i];
        clauses[i].op <== clOp[i];
        clauses[i].value <== clValue[i];
        foldIn[i * 2 + 1] <== clauses[i].meta;
        foldIn[i * 2 + 2] <== clValue[i];
    }
    component fold = H2Chain(MAX_CLAUSES * 2 + 1);
    for (var i = 0; i < MAX_CLAUSES * 2 + 1; i++) fold.in[i] <== foldIn[i];
    clausesHash === fold.out;

    // group aggregation: pass_g = has-active-clause AND all active clauses pass
    signal allPass0[MAX_CLAUSES + 1];
    signal allPass1[MAX_CLAUSES + 1];
    signal noneActive0[MAX_CLAUSES + 1];
    signal noneActive1[MAX_CLAUSES + 1];
    allPass0[0] <== 1;
    allPass1[0] <== 1;
    noneActive0[0] <== 1;
    noneActive1[0] <== 1;
    signal cf0[MAX_CLAUSES];
    signal cf1[MAX_CLAUSES];
    for (var i = 0; i < MAX_CLAUSES; i++) {
        // contribution = 1 - active_g * (1 - pass)
        cf0[i] <== 1 - clauses[i].active0 * (1 - clauses[i].pass);
        cf1[i] <== 1 - clauses[i].active1 * (1 - clauses[i].pass);
        allPass0[i + 1] <== allPass0[i] * cf0[i];
        allPass1[i + 1] <== allPass1[i] * cf1[i];
        noneActive0[i + 1] <== noneActive0[i] * (1 - clauses[i].active0);
        noneActive1[i + 1] <== noneActive1[i] * (1 - clauses[i].active1);
    }
    signal group0Ok <== allPass0[MAX_CLAUSES] * (1 - noneActive0[MAX_CLAUSES]);
    signal group1Ok <== allPass1[MAX_CLAUSES] * (1 - noneActive1[MAX_CLAUSES]);
    signal dnfOk <== group0Ok + group1Ok - group0Ok * group1Ok;
    dnfOk === 1;

    // ---- 8. Session-binding public inputs (account/chain/SM/validUntil/nonce/monitorKeyId) ----
    // These are enforced by the SessionManager against on-chain state; here they are bound as
    // Groth16 public inputs. Add a no-op reference so circom does not treat them as dangling.
    signal bindSink <== account + chainId + sessionManager + validUntil + accountNonce + ordbId + monitorKeyId;
    signal bindSink2 <== bindSink * 0;
    bindSink2 === 0;
}

