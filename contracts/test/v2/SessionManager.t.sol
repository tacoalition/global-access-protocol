// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "../../src/v2/RegimeRegistry.sol";
import "../../src/interfaces/IPoseidon2.sol";
import "forge-std/Test.sol";
import "../../src/v2/SessionManager.sol";
import "../../src/v2/libraries/RelayedGrantAuth.sol";
import "../../src/v2/TransactionFilterV2.sol";
import "../../src/v2/RegulatedTokenV2.sol";
import "../../src/v2/UserPolicyRegistry.sol";
import "../../src/v2/DIDRegistryV2.sol";
import "../../src/v2/IdentityAnchor.sol";
import "../../src/v2/OnchainRiskDatabase.sol";
import "../../src/v2/ClassificationContract.sol";
import "../../src/v2/libraries/GapLib.sol";

contract MockVerifier {
    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[19] calldata)
        external pure returns (bool)
    { return true; }
}

/**
 * @notice GAP-H3 attestation state machine, tested against the REAL SessionManager bindings
 *         (live roots from real registries) with only the Groth16 verifier mocked. Covers the
 *         adversarial findings: unattested sessions are unusable, only the session's ORDB TM
 *         may attest, the attestation digest defeats the front-run-regrant race, and re-grants
 *         always reset attestation.
 */
contract SessionManagerTest is Test {
    address constant TM = address(0x7117);
    bytes32 constant MONITOR_KEY_ID = bytes32(uint256(0xbeef));
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant MALLORY_PK = 0xBAD;
    address constant RELAYER = address(0xDEFACE);

    SessionManager sm;
    UserPolicyRegistry policyReg;
    DIDRegistryV2 didReg;
    IdentityAnchor ita;
    OnchainRiskDatabase ordb;

    /// The holder's pseudonym and its blinding factor: what a TM learns when it decrypts to
    /// attest, and therefore what it already holds when it comes to revoke.
    bytes32 constant PSEUDONYM = bytes32(uint256(0xBEEF));
    bytes32 constant BLINDING_R = bytes32(uint256(0xC0FFEE));
    bytes32 pseudCommit;
    TransactionFilterV2 tf;
    RegulatedTokenV2 tok;
    address token; // == address(tok): sessions/ORDB are scoped to the REAL demo token
    bytes32 policyId;
    bytes32 idRegime;
    bytes32 invRegime;
    address alice;
    address mallory;

    /// The shared regime registry this suite's anchors adopt from (Oct 2026 review, §5.3).
    address internal _regimes;

    function setUp() public {
        alice = vm.addr(ALICE_PK);
        mallory = vm.addr(MALLORY_PK);
        address poseidon = _deployPoseidon();
        string[2] memory _ids;
        _ids[0] = "standard-identity";
        _ids[1] = "investor-status";
        _regimes = _regimeRegistryWith(_ids);
        pseudCommit = IPoseidon2(poseidon).poseidon([PSEUDONYM, BLINDING_R]);
        idRegime = GapLib.regimeHash("standard-identity", 1, 0, 0);
        invRegime = GapLib.regimeHash("investor-status", 1, 0, 0);

        didReg = new DIDRegistryV2(poseidon, 10, 0, address(0));
        ita = new IdentityAnchor(address(this), poseidon, 10, _regimes);
        ita.adoptRegime(idRegime);
        ita.adoptRegime(invRegime);
        policyReg = new UserPolicyRegistry(poseidon, address(this));
        policyReg.setAuthor(address(this), true);
        ClassificationContract cls = new ClassificationContract();
        sm = new SessionManager(address(policyReg), address(didReg), address(cls), address(new MockVerifier()));
        tf = new TransactionFilterV2(address(this), address(sm));
        tok = new RegulatedTokenV2("Test Fund", "TFUND", address(tf), address(this));
        token = address(tok);
        ordb = new OnchainRiskDatabase(address(this), TM, address(this), token, poseidon, 14, 1, 2, MONITOR_KEY_ID);

        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(idRegime, address(ita));
        roots[1] = UserPolicyRegistry.IdentityRootSource(invRegime, address(ita));
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 0, UserPolicyRegistry.ClauseOp.EQ, 840);
        clauses[1] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[2] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[3] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[4] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[5] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        policyReg.approvePredicate(clauses, "us-resident");
        // The holder is flagged in setUp, so the revocation tests below keep testing REVOCATION.
        // The two negatives at the end of this file are what test the precondition itself.
        vm.prank(TM);
        ordb.flagPseudonym(PSEUDONYM, 1);

        policyId = policyReg.registerPolicy("test-policy", roots, address(ordb), clauses, 3600);

        // wire the TF like the deploy script: sender + recipient gating on transfer
        tf.setGatedContract(token);
        bytes32[] memory pols = new bytes32[](1);
        pols[0] = policyId;
        tf.setUserConfig(tok.transfer.selector, pols);
        tf.setRecipientConfig(tok.transfer.selector, true, pols);
    }

    function _deployPoseidon() internal returns (address addr) {
        string[] memory lines = vm.split(vm.readFile("bytecode/Poseidon2.bytecode"), "\n");
        uint256 i = lines.length;
        while (i > 0 && bytes(lines[i - 1]).length == 0) i--;
        bytes memory code = vm.parseBytes(lines[i - 1]);
        assembly { addr := create(0, add(code, 0x20), mload(code)) }
        require(addr != address(0), "poseidon deploy failed");
    }

    function _pub(address account, uint64 validUntil) internal view returns (uint256[19] memory pub) {
        (,,, bytes32 clausesHash,) = policyReg.getPolicyVersion(policyId, 1);
        pub[0] = uint256(uint160(account));
        pub[1] = block.chainid;
        pub[2] = uint256(uint160(address(sm)));
        pub[3] = uint256(clausesHash);
        pub[4] = uint256(validUntil);
        pub[5] = sm.sessionNonce(account);
        pub[6] = uint256(didReg.root());
        pub[7] = uint256(uint160(address(ita)));
        pub[8] = uint256(idRegime);
        pub[9] = uint256(ita.getAttributeRegimeRoot(idRegime));
        pub[10] = uint256(uint160(address(ita)));
        pub[11] = uint256(invRegime);
        pub[12] = uint256(ita.getAttributeRegimeRoot(invRegime));
        pub[13] = uint256(uint160(address(ordb)));
        pub[14] = uint256(ordb.root());
        pub[15] = uint256(uint160(token));
        // A REAL Poseidon commitment, not a placeholder. `revokeSession` now requires the TM to
        // present a pseudonym that reopens this value, so a dummy 111 would make every revocation
        // test unsatisfiable, and, more to the point, the old placeholder meant these tests never
        // exercised the evidence path the TM actually uses.
        pub[16] = uint256(pseudCommit);
        pub[17] = 222; // ikRefCommitment
        pub[18] = uint256(MONITOR_KEY_ID);
    }

    function _grant(uint64 validUntil, bytes memory ciphertext) internal {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        sm.grantSession(policyId, 1, validUntil, a, b, c, _pub(address(this), validUntil), ciphertext);
    }

    function _grantAndAttestFor(address account) internal {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[19] memory pub = _pub(account, vu);
        vm.prank(account);
        sm.grantSession(policyId, 1, vu, a, b, c, pub, "ct");
        bytes32 digest = sm.sessionDigestOf(account, policyId);
        vm.prank(TM);
        sm.attestSession(account, policyId, digest);
    }

    function test_GrantIsUnattestedAndUnusable() public {
        uint64 vu = uint64(block.timestamp + 100);
        _grant(vu, "ct");
        assertFalse(sm.getSession(address(this), policyId).attested);
        assertFalse(sm.hasValidSession(address(this), policyId, token), "unattested must be unusable");
    }

    function test_AttestActivatesSession() public {
        uint64 vu = uint64(block.timestamp + 100);
        _grant(vu, "ct");
        bytes32 digest = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, digest);
        assertTrue(sm.hasValidSession(address(this), policyId, token));
    }

    function test_AttestOnlySessionTM() public {
        _grant(uint64(block.timestamp + 100), "ct");
        bytes32 digest = sm.sessionDigestOf(address(this), policyId);
        vm.expectRevert("SM: not session TM");
        sm.attestSession(address(this), policyId, digest); // caller = this, not TM
    }

    function test_AttestWrongDigestReverts() public {
        _grant(uint64(block.timestamp + 100), "ct");
        vm.prank(TM);
        vm.expectRevert("SM: session digest mismatch");
        sm.attestSession(address(this), policyId, bytes32(uint256(1)));
    }

    /// Audit (venue round): a strengthened policy must not be sidestepped by granting against a
    /// weaker HISTORICAL version, new grants only ever target the latest version.
    function test_GrantOnStalePolicyVersionReverts() public {
        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(idRegime, address(ita));
        roots[1] = UserPolicyRegistry.IdentityRootSource(invRegime, address(ita));
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 0, UserPolicyRegistry.ClauseOp.EQ, 840);
        clauses[1] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0); // stricter v2
        policyReg.approvePredicate(clauses, "us-resident-not-sanctioned"); // v2 is a different predicate
        policyReg.updatePolicy(policyId, roots, address(ordb), clauses, 3600);

        uint64 vu = uint64(block.timestamp + 100);
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[19] memory pub = _pub(address(this), vu);
        vm.expectRevert("SM: stale policy version");
        sm.grantSession(policyId, 1, vu, a, b, c, pub, "ct"); // v1 is stale now that v2 exists
    }

    function test_AttestNoSessionReverts() public {
        vm.expectRevert("SM: no session");
        sm.attestSession(address(this), bytes32(uint256(42)), bytes32(0));
    }

    /// The audited front-run race: TM attests S1 by digest; user re-grants S2 (garbage
    /// ciphertext) before the attest lands. The digest binds to S1's stored bytes, so the
    /// in-flight attestation must NOT activate S2.
    function test_FrontRunRegrantCannotInheritAttestation() public {
        uint64 vu = uint64(block.timestamp + 100);
        _grant(vu, "honest-ciphertext");
        bytes32 digestS1 = sm.sessionDigestOf(address(this), policyId);
        _grant(vu, "garbage"); // re-grant overwrites (nonce bumped inside _pub via sessionNonce)
        vm.prank(TM);
        vm.expectRevert("SM: session digest mismatch");
        sm.attestSession(address(this), policyId, digestS1);
        assertFalse(sm.hasValidSession(address(this), policyId, token));
    }

    /// GAP-H6 token-level, end-to-end: token → TF → SM. No session → sender blocked; sender
    /// session only → recipient blocked; both attested sessions → transfer passes. This is the
    /// wiring the TF-level tests can't see (audit finding).
    function test_TokenLevelBothSideGating() public {
        address recipient = address(0x4EC1);
        tok.mint(address(this), 100 ether);

        vm.expectRevert("RT: sender not compliant");
        tok.transfer(recipient, 1 ether);

        _grantAndAttestFor(address(this));
        vm.expectRevert("RT: recipient not compliant");
        tok.transfer(recipient, 1 ether);

        _grantAndAttestFor(recipient);
        assertTrue(tok.transfer(recipient, 1 ether));
        assertEq(tok.balanceOf(recipient), 1 ether);
    }

    /// GAP-H6 tri-state recipient gate: UNSET fails closed, DISABLED is an explicit sender-only
    /// choice, ENABLED requires an attested receiving session proven for the gated contract.
    function test_RecipientGatingTriState() public {
        TransactionFilterV2 tf = new TransactionFilterV2(address(this), address(sm));
        tf.setGatedContract(token);
        bytes4 sel = bytes4(0x12345678);
        assertFalse(tf.checkRecipient(sel, address(this)), "UNSET must fail closed");
        tf.setRecipientConfig(sel, false, new bytes32[](0));
        assertTrue(tf.checkRecipient(sel, address(this)), "DISABLED is explicitly open");
        bytes32[] memory pols = new bytes32[](1);
        pols[0] = policyId;
        tf.setRecipientConfig(sel, true, pols);
        assertFalse(tf.checkRecipient(sel, address(this)), "ENABLED without a session must deny");
        _grant(uint64(block.timestamp + 100), "ct");
        assertFalse(tf.checkRecipient(sel, address(this)), "unattested receiving session must deny");
        bytes32 digest = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, digest);
        assertTrue(tf.checkRecipient(sel, address(this)), "attested receiving session must pass");
    }

    /// The audited property, re-scoped to the session a grant actually INSTALLS: a grant never
    /// writes `attested`. Here the live session has lapsed, so the re-grant lands in the live slot
    /// directly and must come back unattested.
    function test_RegrantResetsAttestation() public {
        uint64 vu = uint64(block.timestamp + 100);
        _grant(vu, "ct-1");
        bytes32 digest = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, digest);
        assertTrue(sm.hasValidSession(address(this), policyId, token));

        vm.warp(block.timestamp + 101); // lapsed → the re-grant installs in place
        _grant(uint64(block.timestamp + 100), "ct-2"); // fresh ciphertext → attestation must not carry over
        assertFalse(sm.getSession(address(this), policyId).attested, "re-grant must reset attested");
        assertFalse(sm.hasValidSession(address(this), policyId, token));
        assertEq(sm.getPendingSession(address(this), policyId).validUntil, 0, "no stage on the direct path");
    }

    // ---------------- non-destructive re-grant (staged renewal) ----------------

    /// A re-grant used to overwrite the live slot and reset `attested`, so ANY early renewal took
    /// the account dark until the TM re-attested: a self-inflicted DoS. The new session is now
    /// staged; the live attested one keeps serving until the stage is attested.
    function test_UnattestedRegrantCannotKillLiveAttestedSession() public {
        uint64 vu = uint64(block.timestamp + 100);
        _grant(vu, "ct-1");
        bytes32 d0 = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, d0);
        assertTrue(sm.hasValidSession(address(this), policyId, token));

        _grant(vu, "ct-2"); // early renewal
        assertTrue(sm.hasValidSession(address(this), policyId, token), "live session must survive a re-grant");
        SessionManager.UserSession memory staged = sm.getPendingSession(address(this), policyId);
        assertEq(staged.validUntil, vu, "renewal must be staged");
        assertFalse(staged.attested, "a staged grant is never attested");
        assertEq(sm.getSession(address(this), policyId).encryptedPseudonym, abi.encode(pseudCommit, uint256(222), uint256(MONITOR_KEY_ID), bytes("ct-1")));
    }

    function test_StagedRenewalPromotedOnAttestation() public {
        uint64 vu = uint64(block.timestamp + 100);
        _grant(vu, "ct-1");
        bytes32 d0 = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, d0);

        uint64 vu2 = uint64(block.timestamp + 200);
        _grant(vu2, "ct-2");
        bytes32 stagedDigest = sm.pendingSessionDigestOf(address(this), policyId);
        assertEq(sm.sessionDigestOf(address(this), policyId), stagedDigest, "digest helper must point at the stage");

        vm.prank(TM);
        sm.attestSession(address(this), policyId, stagedDigest);
        SessionManager.UserSession memory live = sm.getSession(address(this), policyId);
        assertTrue(live.attested);
        assertEq(live.validUntil, vu2);
        assertEq(live.encryptedPseudonym, abi.encode(pseudCommit, uint256(222), uint256(MONITOR_KEY_ID), bytes("ct-2")));
        assertEq(sm.getPendingSession(address(this), policyId).validUntil, 0, "stage must be consumed");
        assertTrue(sm.hasValidSession(address(this), policyId, token));
    }

    /// An expired stage must not be promotable over a live attested session.
    function test_ExpiredStageCannotDisplaceLiveSession() public {
        _grant(uint64(block.timestamp + 1000), "ct-1");
        bytes32 d0 = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, d0);

        _grant(uint64(block.timestamp + 10), "ct-2"); // short-lived stage
        bytes32 stagedDigest = sm.pendingSessionDigestOf(address(this), policyId);
        vm.warp(block.timestamp + 11);
        vm.prank(TM);
        vm.expectRevert("SM: staged expired");
        sm.attestSession(address(this), policyId, stagedDigest);
        assertTrue(sm.hasValidSession(address(this), policyId, token), "live session untouched");
    }

    /// A stale stage must never outrank a newer direct install.
    function test_DirectInstallClearsStaleStage() public {
        _grant(uint64(block.timestamp + 100), "ct-1");
        bytes32 d0 = sm.sessionDigestOf(address(this), policyId);
        vm.prank(TM);
        sm.attestSession(address(this), policyId, d0);
        _grant(uint64(block.timestamp + 100), "ct-2"); // staged
        vm.warp(block.timestamp + 101);                // both lapse
        _grant(uint64(block.timestamp + 100), "ct-3"); // installs directly
        assertEq(sm.getPendingSession(address(this), policyId).validUntil, 0, "stale stage must be cleared");
    }

    // ---------------- explicit revocation ----------------

    function test_RevokeByAttestorInvalidatesImmediately() public {
        _grantAndAttestFor(alice);
        assertTrue(sm.hasValidSession(alice, policyId, token));
        vm.prank(TM);
        vm.expectEmit(true, true, false, true, address(sm));
        emit SessionRevoked(alice, policyId, TM);
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);
        assertFalse(sm.hasValidSession(alice, policyId, token), "revocation must take effect at once");
        assertEq(sm.getSession(alice, policyId).validUntil, 0);
    }

    function test_RevokeByNonAttestorReverts() public {
        _grantAndAttestFor(alice);
        vm.prank(RELAYER);
        vm.expectRevert("SM: not session TM");
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);
        vm.expectRevert("SM: not session TM"); // the SM admin-less design: even `this` is not an authority
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);
        assertTrue(sm.hasValidSession(alice, policyId, token));
    }

    function test_RevokeIsIdempotentAndSafeOnMissingSession() public {
        sm.revokeSession(address(0xD00D), bytes32(uint256(77)), PSEUDONYM, BLINDING_R); // never existed → silent no-op
        _grantAndAttestFor(alice);
        vm.prank(TM);
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);
        vm.prank(TM);
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R); // second call is a no-op, not a revert
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R); // and needs no authority once the slot is empty
        assertFalse(sm.hasValidSession(alice, policyId, token));
    }

    function test_RevokeClearsStagedRenewalAndStaleAttestation() public {
        _grantAndAttestFor(alice);
        uint64 vu = uint64(block.timestamp + 200);
        _grantFor(alice, vu, "ct-staged");
        bytes32 stagedDigest = sm.pendingSessionDigestOf(alice, policyId);

        vm.prank(TM);
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);
        assertEq(sm.getPendingSession(alice, policyId).validUntil, 0, "stage must go with the revocation");
        vm.prank(TM);
        vm.expectRevert("SM: no session");
        sm.attestSession(alice, policyId, stagedDigest); // in-flight attestation cannot resurrect it
    }

    /// Revocation bumps the account nonce so a relayer sitting on an unexpired authorization
    /// cannot immediately re-install the session the TM just revoked.
    function test_RevocationBurnsHeldRelayedSignature() public {
        _grantAndAttestFor(alice);
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "ct");

        vm.prank(TM);
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);

        vm.expectRevert("SM: grant signer mismatch"); // nonce moved → the digest no longer recovers to alice
        _submit(g, pub, "ct", sig);
    }

    // ---------------- relayed grants (EIP-712) ----------------

    function test_RelayedGrantByThirdPartySender() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        uint256 nonceBefore = sm.sessionNonce(alice);

        _submit(g, pub, "ct", _signGrant(ALICE_PK, g, pub, "ct"));

        SessionManager.UserSession memory s = sm.getSession(alice, policyId);
        assertEq(s.validUntil, vu, "session stored under the SIGNER, not the sender");
        assertEq(s.gatedContract, token);
        assertEq(s.ordb, address(ordb));
        assertFalse(s.attested, "relayed grants are unattested like any other");
        assertEq(sm.sessionNonce(alice), nonceBefore + 1);
        assertEq(sm.sessionNonce(RELAYER), 0, "the relayer's own nonce must be untouched");

        bytes32 dAlice = sm.sessionDigestOf(alice, policyId);
        vm.prank(TM);
        sm.attestSession(alice, policyId, dAlice);
        assertTrue(sm.hasValidSession(alice, policyId, token));
    }

    function test_RelayedGrantWrongSignerRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes memory sig = _signGrant(MALLORY_PK, g, pub, "ct");
        vm.expectRevert("SM: grant signer mismatch");
        _submit(g, pub, "ct", sig);
    }

    /// The receiver-impersonation mitigation survives relaying: mallory cannot install a session
    /// for alice, and alice's own signature cannot be re-aimed at another account.
    function test_RelayedGrantCrossAccountRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pubM = _pub(mallory, vu);
        RelayedGrantAuth.SessionGrant memory forMallory = _grantParams(mallory, vu, block.timestamp + 1 hours);
        bytes memory malloryScopedSig = _signGrant(MALLORY_PK, forMallory, pubM, "ct");

        // re-aim mallory's authorization at alice's slot
        RelayedGrantAuth.SessionGrant memory forAlice = _grantParams(alice, vu, block.timestamp + 1 hours);
        uint256[19] memory pubA = _pub(alice, vu);
        bytes memory aliceSig = _signGrant(ALICE_PK, forAlice, pubA, "ct");
        vm.expectRevert("SM: grant signer mismatch");
        _submit(forAlice, pubA, "ct", malloryScopedSig);

        // and a valid alice signature cannot be replayed into mallory's slot
        vm.expectRevert("SM: grant signer mismatch");
        _submit(forMallory, pubM, "ct", aliceSig);
        assertEq(sm.getSession(alice, policyId).validUntil, 0);
        assertEq(sm.getSession(mallory, policyId).validUntil, 0);
    }

    function test_RelayedGrantTamperedPubRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "ct");
        pub[16] = 999; // swap the pseudonym commitment the TM will be asked to reopen
        vm.expectRevert("SM: grant signer mismatch");
        _submit(g, pub, "ct", sig);
    }

    /// The proof does NOT bind `ciphertext` (Spike-A option 3), so the signature must, otherwise a
    /// relayer could swap it and strand the session unattestable.
    function test_RelayedGrantTamperedCiphertextRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "honest-ciphertext");
        vm.expectRevert("SM: grant signer mismatch");
        _submit(g, pub, "garbage", sig);
    }

    function test_RelayedGrantExpiredDeadlineRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 60);
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "ct");
        vm.warp(block.timestamp + 61);
        vm.expectRevert("SM: grant deadline passed");
        _submit(g, pub, "ct", sig);
    }

    function test_RelayedGrantReplayRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "ct");
        _submit(g, pub, "ct", sig);
        vm.expectRevert("SM: grant signer mismatch"); // sessionNonce moved under the signature
        _submit(g, pub, "ct", sig);
    }

    function test_RelayedGrantWrongChainIdDomainRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);

        bytes32 foreignDomain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("GAP SessionManager"),
            keccak256("2"),
            block.chainid + 1, // signed for a different chain
            address(sm)
        ));
        bytes32 structHash = keccak256(abi.encode(
            RelayedGrantAuth.RELAYED_GRANT_TYPEHASH, g.account, g.policyId, g.policyVersion, g.validUntil,
            keccak256(abi.encode(pub)), keccak256(bytes("ct")), sm.sessionNonce(alice), g.deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", foreignDomain, structHash)));
        vm.expectRevert("SM: grant signer mismatch");
        _submit(g, pub, "ct", abi.encodePacked(r, s, v));
    }

    /// Same struct, wrong verifyingContract: the other half of the domain binding.
    function test_RelayedGrantForeignVerifyingContractRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes32 foreignDomain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("GAP SessionManager"),
            keccak256("2"),
            block.chainid,
            address(0xC0FFEE)
        ));
        bytes32 structHash = keccak256(abi.encode(
            RelayedGrantAuth.RELAYED_GRANT_TYPEHASH, g.account, g.policyId, g.policyVersion, g.validUntil,
            keccak256(abi.encode(pub)), keccak256(bytes("ct")), sm.sessionNonce(alice), g.deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", foreignDomain, structHash)));
        vm.expectRevert("SM: grant signer mismatch");
        _submit(g, pub, "ct", abi.encodePacked(r, s, v));
    }

    /// pub[0] is still checked against the AUTHORIZING account, not msg.sender: a correctly signed
    /// grant whose proof names someone else's address is rejected by the account binding.
    function test_RelayedGrantPubAccountBindingStillEnforced() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        pub[0] = uint256(uint160(mallory)); // proof is for mallory, authorization is alice's
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "ct");
        vm.expectRevert("SM: account binding");
        _submit(g, pub, "ct", sig);
    }

    function test_RelayedGrantMalformedSignatureRejected() public {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        vm.expectRevert("SM: malformed grant signature");
        _submit(g, pub, "ct", hex"1234");

        // high-s malleable variant of a valid signature
        bytes memory sig = _signGrant(ALICE_PK, g, pub, "ct");
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        uint256 flippedS =
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s);
        vm.expectRevert("SM: malformed grant signature");
        _submit(g, pub, "ct", abi.encodePacked(r, bytes32(flippedS), v == 27 ? uint8(28) : uint8(27)));
    }

    /// A relayed grant renews non-destructively too.
    function test_RelayedRegrantStagesInsteadOfKilling() public {
        _grantAndAttestFor(alice);
        assertTrue(sm.hasValidSession(alice, policyId, token));
        uint64 vu = uint64(block.timestamp + 200);
        uint256[19] memory pub = _pub(alice, vu);
        RelayedGrantAuth.SessionGrant memory g = _grantParams(alice, vu, block.timestamp + 1 hours);
        _submit(g, pub, "ct-2", _signGrant(ALICE_PK, g, pub, "ct-2"));
        assertTrue(sm.hasValidSession(alice, policyId, token), "live session survives a relayed renewal");
        assertEq(sm.getPendingSession(alice, policyId).validUntil, vu);
    }

    // ---------------- helpers ----------------

    event SessionRevoked(address indexed account, bytes32 indexed policyId, address revoker);

    function _grantParams(address account, uint64 vu, uint256 deadline)
        internal
        view
        returns (RelayedGrantAuth.SessionGrant memory)
    {
        return RelayedGrantAuth.SessionGrant(account, policyId, 1, vu, deadline);
    }

    function _signGrant(
        uint256 pk,
        RelayedGrantAuth.SessionGrant memory g,
        uint256[19] memory pub,
        bytes memory ciphertext
    ) internal view returns (bytes memory) {
        bytes32 digest =
            sm.relayedGrantDigest(g, keccak256(abi.encode(pub)), keccak256(ciphertext), sm.sessionNonce(g.account));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _submit(
        RelayedGrantAuth.SessionGrant memory g,
        uint256[19] memory pub,
        bytes memory ciphertext,
        bytes memory signature
    ) internal {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.prank(RELAYER);
        sm.grantSessionFor(g, a, b, c, pub, ciphertext, signature);
    }

    function _grantFor(address account, uint64 vu, bytes memory ciphertext) internal {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[19] memory pub = _pub(account, vu); // resolve views BEFORE the prank
        vm.prank(account);
        sm.grantSession(policyId, 1, vu, a, b, c, pub, ciphertext);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
    }

    // ---------------- the revocation precondition (Oct 2026 review, §5.2) ----------------

    /**
     * The paper (p.19, §6.3) promises no party can dynamically invalidate a session. We depart from
     * that deliberately, but the departure now has to show its grounds on chain.
     */
    function test_RevokeWithoutAFlagIsRefused() public {
        _grantAndAttestFor(alice);
        vm.prank(TM);
        ordb.proposeUnflag(PSEUDONYM, 1);     // the monitor raises the appeal
        ordb.unflagPseudonym(PSEUDONYM, 1);   // governance clears it, onlyGovernance IS address(this)
        vm.prank(TM);
        vm.expectRevert("SM: no flagged grounds");
        sm.revokeSession(alice, policyId, PSEUDONYM, BLINDING_R);
        assertTrue(sm.hasValidSession(alice, policyId, token), "an unflagged holder keeps their session");
    }

    /**
     * The binding half, and the one that matters most. A TM knows pseudonyms that ARE flagged: its
     * own book is full of them. Without tying the evidence to this session's commitment, any of them
     * would serve as grounds against any account.
     */
    function test_AFlaggedPseudonymFromAnotherHolderIsNotGrounds() public {
        _grantAndAttestFor(alice);
        bytes32 someoneElse = bytes32(uint256(0xDEAD));
        vm.prank(TM);
        ordb.flagPseudonym(someoneElse, 1);   // genuinely flagged, genuinely not alice's
        vm.prank(TM);
        vm.expectRevert("SM: no flagged grounds");
        sm.revokeSession(alice, policyId, someoneElse, BLINDING_R);
        assertTrue(sm.hasValidSession(alice, policyId, token), "another holder's flag is not grounds");
    }

    /// @dev Regimes must exist in the shared registry before an anchor can adopt them (Oct 2026
    ///      review, §5.3). This seeds the ones this suite uses; the ids are the same strings the
    ///      `GapLib.regimeHash` calls derive from, so the hashes match by construction.
    function _regimeRegistryWith(string[2] memory ids) internal returns (address) {
        RegimeRegistry r = new RegimeRegistry(0, address(0));
        for (uint256 i = 0; i < ids.length; i++) {
            r.proposeRegime(ids[i], 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, ids[i], "", 4);
        }
        return address(r);
    }

    // ---------- the binding layer, asserted slot by slot ----------

    /**
     * EVERY PINNING `require` MUST BE LOAD-BEARING, AND TWELVE OF THEM WERE NOT.
     *
     * A reviewer deleted each binding in `_checkBindings` in turn and re-ran this suite. Only
     * `account binding` and `stale policy version` failed. The other twelve, including
     * `stale risk root`, the control that makes a TM flag bite, and `nonce binding`, the replay
     * nullifier, could be deleted outright with 139/139 green.
     *
     * The cause was structural rather than careless: almost every test here injects a MockVerifier
     * and then builds `pub[]` out of the same live state the contract checks it against, so the
     * bindings hold by construction and removing one changes no outcome. Nothing ever supplied a
     * MISMATCHED `pub[]`.
     *
     * It matters because `_checkBindings` is the natural extension point: a third regime, another
     * public slot, a different ORDB topology, and the failure mode of getting it wrong is a session
     * that verifies against state other than the chain's. Silent, and precisely what this layer is
     * for.
     *
     * So each case corrupts exactly one slot of an otherwise-satisfying array and asserts the revert
     * that names it. A table, because the point is covering every slot rather than any one case.
     */
    function _expectBindingRevert(uint256 slot, uint256 wrongValue, string memory err) internal {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[19] memory pub = _pub(address(this), vu);
        pub[slot] = wrongValue;
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        // Everything that reads chain state is already done: `_pub` calls `sessionNonce`, `root()`
        // and `getAttributeRegimeRoot`, so expecting the revert any earlier binds the cheatcode to
        // one of those view calls and the test passes for the wrong reason.
        vm.expectRevert(bytes(err));
        sm.grantSession(policyId, 1, vu, a, b, c, pub, "ct");
    }

    /// A wrong-but-well-formed value for a slot: in-field and the right shape, so the revert under
    /// test is the binding itself and not a range check somewhere upstream.
    function _bumped(uint256 slot) internal view returns (uint256) {
        return _pub(address(this), uint64(block.timestamp + 100))[slot] + 1;
    }

    function test_AccountChainAndSessionManagerBindingsAreChecked() public {
        _expectBindingRevert(0, _bumped(0), "SM: account binding");
        _expectBindingRevert(1, _bumped(1), "SM: chainId binding");
        _expectBindingRevert(2, _bumped(2), "SM: SM binding");
    }

    function test_ValidUntilAndNonceBindingsAreChecked() public {
        _expectBindingRevert(4, _bumped(4), "SM: validUntil binding");
        _expectBindingRevert(5, _bumped(5), "SM: nonce binding");
    }

    function test_PredicateAndDidRootBindingsAreChecked() public {
        _expectBindingRevert(3, _bumped(3), "SM: predicate binding");
        _expectBindingRevert(6, _bumped(6), "SM: stale DID root");
    }

    function test_BothRegimeTriplesArePinnedIndependently() public {
        // The loop in `_checkPolicyBindings` indexes at `o = 7 + i*3`; an off-by-one there would
        // leave one regime unchecked, so both triples are corrupted separately.
        _expectBindingRevert(7, _bumped(7), "SM: ITA binding");
        _expectBindingRevert(8, _bumped(8), "SM: regime binding");
        _expectBindingRevert(9, _bumped(9), "SM: stale credential root");
        _expectBindingRevert(10, _bumped(10), "SM: ITA binding");
        _expectBindingRevert(11, _bumped(11), "SM: regime binding");
        _expectBindingRevert(12, _bumped(12), "SM: stale credential root");
    }

    function test_OrdbRiskRootAndGatedContractBindingsAreChecked() public {
        _expectBindingRevert(13, _bumped(13), "SM: ORDB binding");
        _expectBindingRevert(14, _bumped(14), "SM: stale risk root");
        _expectBindingRevert(15, uint256(uint160(address(0xDEAD))), "SM: gated-contract binding");
    }

    function test_MonitorKeyBindingIsChecked() public {
        _expectBindingRevert(18, _bumped(18), "SM: monitor key binding");
    }
}
