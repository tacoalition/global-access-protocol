// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "../../src/v2/RegimeRegistry.sol";
import "forge-std/Test.sol";
import "../../src/v2/RegulatedVenueV2.sol";
import "../../src/v2/SessionManager.sol";
import "../../src/v2/UserPolicyRegistry.sol";
import "../../src/v2/DIDRegistryV2.sol";
import "../../src/v2/IdentityAnchor.sol";
import "../../src/v2/OnchainRiskDatabase.sol";
import "../../src/v2/ClassificationContract.sol";
import "../../src/v2/libraries/GapLib.sol";

contract VenueMockVerifier {
    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[19] calldata)
        external pure returns (bool)
    { return true; }
}

/**
 * @notice RegulatedVenueV2 acceptance (design: ZONES_AND_VENUE_DESIGN.md (full stack, not in this repository)): venue-
 *         level gating over zones, with real SessionManager bindings (mock verifier only).
 *         Covers the plan-audit findings: ORDB wiring coherence, zone-policy role coherence,
 *         both-side session gates per zone, cross-zone isolation without session eviction,
 *         issuance ledger, destination-constrained operator powers, immediate re-zoning.
 */
contract RegulatedVenueTest is Test {
    bytes32 constant MONITOR_KEY_ID = bytes32(uint256(0xfeed));
    bytes32 constant ZONE_GENERAL = keccak256("general");
    bytes32 constant ZONE_REGD = keccak256("reg-d");
    bytes32 constant ZONE_ENTITY = keccak256("entity");
    bytes32 constant FUND = keccak256("asset:dFUND-G");
    bytes32 constant PRIV = keccak256("asset:PRIV-D");
    bytes32 constant ENTB = keccak256("asset:ENT-B");

    SessionManager sm;
    UserPolicyRegistry policyReg;
    DIDRegistryV2 didReg;
    IdentityAnchor ita;
    RegulatedVenueV2 venue;
    OnchainRiskDatabase venueOrdb;
    address poseidon;

    bytes32 idRegime;
    bytes32 invRegime;
    bytes32 kybRegime;

    bytes32 genT; bytes32 genR;   // general zone policy pair
    bytes32 regdT; bytes32 regdR; // reg-d zone policy pair
    bytes32 entT; bytes32 entR;   // entity zone policy pair

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    /// The shared regime registry this suite's anchors adopt from (Oct 2026 review, §5.3).
    address internal _regimes;

    function setUp() public {
        poseidon = _deployPoseidon();
        string[3] memory _ids;
        _ids[0] = "standard-identity";
        _ids[1] = "investor-status";
        _ids[2] = "entity-kyb";
        _regimes = _regimeRegistryWith(_ids);
        idRegime = GapLib.regimeHash("standard-identity", 1, 0, 0);
        invRegime = GapLib.regimeHash("investor-status", 1, 0, 0);
        kybRegime = GapLib.regimeHash("entity-kyb", 1, 0, 0);

        didReg = new DIDRegistryV2(poseidon, 10, 0, address(0));
        ita = new IdentityAnchor(address(this), poseidon, 10, _regimes);
        ita.adoptRegime(idRegime);
        ita.adoptRegime(invRegime);
        ita.adoptRegime(kybRegime);
        policyReg = new UserPolicyRegistry(poseidon, address(this));
        policyReg.setAuthor(address(this), true);
        policyReg.setAuthor(alice, true); // test_RegisterZoneEnforcesPolicyCoherence registers as alice
        sm = new SessionManager(
            address(policyReg), address(didReg), address(new ClassificationContract()), address(new VenueMockVerifier())
        );

        // venue first, then its ORDB (constructor needs monitoredContract = venue), then wire
        venue = new RegulatedVenueV2(address(this), address(sm));
        venueOrdb = new OnchainRiskDatabase(
            address(this), address(this), address(this), address(venue), poseidon, 14, 1, 2, MONITOR_KEY_ID
        );
        venue.initOrdb(address(venueOrdb));

        (genT, genR) = _registerZonePolicies("general", idRegime, invRegime);
        (regdT, regdR) = _registerZonePolicies("reg-d", idRegime, invRegime);
        (entT, entR) = _registerZonePolicies("entity", idRegime, kybRegime);
        venue.registerZone(ZONE_GENERAL, genT, genR);
        venue.registerZone(ZONE_REGD, regdT, regdR);
        venue.registerZone(ZONE_ENTITY, entT, entR);
        venue.registerAsset(FUND, "dFUND-G", ZONE_GENERAL);
        venue.registerAsset(PRIV, "PRIV-D", ZONE_REGD);
        venue.registerAsset(ENTB, "ENT-B", ZONE_ENTITY);
    }

    function _registerZonePolicies(string memory zoneName, bytes32 r0, bytes32 r1)
        internal returns (bytes32 transferId, bytes32 receivingId)
    {
        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(r0, address(ita));
        roots[1] = UserPolicyRegistry.IdentityRootSource(r1, address(ita));
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);
        clauses[1] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[2] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[3] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[4] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[5] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        // The "foreign" and "wrong-ordb" policies below carry this same predicate (an explicit
        // NONE filler is the zero value), so one approval covers every policy in this suite.
        policyReg.approvePredicate(clauses, "not-sanctioned");
        transferId = policyReg.registerPolicy(string.concat(zoneName, "-transfer"), roots, address(venueOrdb), clauses, 3600);
        receivingId = policyReg.registerPolicy(string.concat(zoneName, "-receiving"), roots, address(venueOrdb), clauses, 86400);
    }

    function _deployPoseidon() internal returns (address addr) {
        string[] memory lines = vm.split(vm.readFile("bytecode/Poseidon2.bytecode"), "\n");
        uint256 i = lines.length;
        while (i > 0 && bytes(lines[i - 1]).length == 0) i--;
        bytes memory code = vm.parseBytes(lines[i - 1]);
        assembly { addr := create(0, add(code, 0x20), mload(code)) }
        require(addr != address(0), "poseidon deploy failed");
    }

    /// Build the 19 public inputs for any (account, policy) from the policy's OWN registry entry.
    function _pubFor(address account, bytes32 policyId, uint64 validUntil)
        internal view returns (uint256[19] memory pub)
    {
        (UserPolicyRegistry.IdentityRootSource[2] memory roots, address requiredORDB,, bytes32 clausesHash,) =
            policyReg.getPolicyVersion(policyId, 1);
        OnchainRiskDatabase o = OnchainRiskDatabase(requiredORDB);
        (,, bytes32 keyId) = o.getMonitorKey();
        pub[0] = uint256(uint160(account));
        pub[1] = block.chainid;
        pub[2] = uint256(uint160(address(sm)));
        pub[3] = uint256(clausesHash);
        pub[4] = uint256(validUntil);
        pub[5] = sm.sessionNonce(account);
        pub[6] = uint256(didReg.root());
        for (uint256 i = 0; i < 2; i++) {
            pub[7 + i * 3] = uint256(uint160(roots[i].ita));
            pub[8 + i * 3] = uint256(roots[i].regimeHash);
            pub[9 + i * 3] = uint256(ita.getAttributeRegimeRoot(roots[i].regimeHash));
        }
        pub[13] = uint256(uint160(requiredORDB));
        pub[14] = uint256(o.root());
        pub[15] = uint256(uint160(o.monitoredContract()));
        pub[16] = 111;
        pub[17] = 222;
        pub[18] = uint256(keyId);
    }

    function _grant(address account, bytes32 policyId) internal {
        uint64 vu = uint64(block.timestamp + 1800);
        uint256[2] memory a; uint256[2][2] memory b; uint256[2] memory c;
        uint256[19] memory pub = _pubFor(account, policyId, vu);
        vm.prank(account);
        sm.grantSession(policyId, 1, vu, a, b, c, pub, "ct");
    }

    function _grantAttest(address account, bytes32 policyId) internal {
        _grant(account, policyId);
        sm.attestSession(account, policyId, sm.sessionDigestOf(account, policyId)); // this == TM
    }

    // ---------- wiring coherence (audit findings) ----------

    function test_InitOrdbCoherenceChecks() public {
        RegulatedVenueV2 v2 = new RegulatedVenueV2(address(this), address(sm));
        // ORDB scoped to a DIFFERENT contract is rejected
        OnchainRiskDatabase wrongScope = new OnchainRiskDatabase(
            address(this), address(this), address(this), address(0xDEAD), poseidon, 14, 1, 2, MONITOR_KEY_ID
        );
        vm.expectRevert("Venue: ordb not scoped here");
        v2.initOrdb(address(wrongScope));
        // ORDB whose TM is not the operator is rejected
        OnchainRiskDatabase wrongTm = new OnchainRiskDatabase(
            address(this), address(0xBAD), address(this), address(v2), poseidon, 14, 1, 2, MONITOR_KEY_ID
        );
        vm.expectRevert("Venue: ordb TM mismatch");
        v2.initOrdb(address(wrongTm));
        // double-init is rejected
        vm.expectRevert("Venue: ordb set");
        venue.initOrdb(address(venueOrdb));
    }

    function test_RegisterZoneEnforcesPolicyCoherence() public {
        // a policy owned by someone else cannot back a zone
        vm.startPrank(alice);
        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(idRegime, address(ita));
        roots[1] = UserPolicyRegistry.IdentityRootSource(invRegime, address(ita));
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);
        bytes32 foreign = policyReg.registerPolicy("foreign", roots, address(venueOrdb), clauses, 3600);
        vm.stopPrank();
        vm.expectRevert("Venue: policy not operator-owned");
        venue.registerZone(keccak256("z2"), foreign, foreign);

        // a policy naming a different ORDB cannot back a zone
        OnchainRiskDatabase other = new OnchainRiskDatabase(
            address(this), address(this), address(this), address(0xDEAD), poseidon, 14, 1, 2, MONITOR_KEY_ID
        );
        bytes32 wrongOrdb = policyReg.registerPolicy("wrong-ordb", roots, address(other), clauses, 3600);
        vm.expectRevert("Venue: policy ORDB mismatch");
        venue.registerZone(keccak256("z3"), wrongOrdb, wrongOrdb);
    }

    function test_RegisterZoneUnknownPolicyReverts() public {
        vm.expectRevert("Policy: not found");
        venue.registerZone(keccak256("z4"), keccak256("no-such-policy"), keccak256("no-such-policy"));
    }

    /// Cross-venue policy reuse fails closed: a second venue (own ORDB) cannot register a zone
    /// backed by a policy that names the FIRST venue's ORDB.
    function test_CrossVenuePolicyReuseFailsClosed() public {
        RegulatedVenueV2 v2 = new RegulatedVenueV2(address(this), address(sm));
        OnchainRiskDatabase o2 = new OnchainRiskDatabase(
            address(this), address(this), address(this), address(v2), poseidon, 14, 1, 2, MONITOR_KEY_ID
        );
        v2.initOrdb(address(o2));
        vm.expectRevert("Venue: policy ORDB mismatch");
        v2.registerZone(ZONE_GENERAL, genT, genR); // genT/genR name venue #1's ORDB
    }

    // ---------- gated transfers ----------

    function test_TransferRequiresBothSessions() public {
        venue.issue(FUND, alice, 100);
        vm.prank(alice);
        vm.expectRevert("Venue: sender not compliant");
        venue.transfer(FUND, bob, 10);

        _grantAttest(alice, genT);
        vm.prank(alice);
        vm.expectRevert("Venue: recipient not compliant");
        venue.transfer(FUND, bob, 10);

        _grantAttest(bob, genR);
        vm.prank(alice);
        venue.transfer(FUND, bob, 10);
        assertEq(venue.balanceOf(FUND, alice), 90);
        assertEq(venue.balanceOf(FUND, bob), 10);
    }

    function test_UnattestedReceivingSessionBlocks() public {
        venue.issue(FUND, alice, 100);
        _grantAttest(alice, genT);
        _grant(bob, genR); // granted but NOT attested (GAP-H3)
        vm.prank(alice);
        vm.expectRevert("Venue: recipient not compliant");
        venue.transfer(FUND, bob, 10);
    }

    function test_ExpiredSessionBlocks() public {
        venue.issue(FUND, alice, 100);
        _grantAttest(alice, genT);
        _grantAttest(bob, genR);
        vm.warp(block.timestamp + 1801); // past the transfer session's validUntil
        vm.prank(alice);
        vm.expectRevert("Venue: sender not compliant");
        venue.transfer(FUND, bob, 10);
    }

    function test_CrossZoneIsolationWithoutEviction() public {
        venue.issue(FUND, alice, 100);
        venue.issue(PRIV, alice, 100);
        _grantAttest(alice, genT);
        _grantAttest(bob, genR);
        // general sessions do NOT satisfy the reg-d asset
        vm.prank(alice);
        vm.expectRevert("Venue: sender not compliant");
        venue.transfer(PRIV, bob, 5);
        // granting the reg-d pair unlocks it, and the general sessions still work (no eviction)
        _grantAttest(alice, regdT);
        _grantAttest(bob, regdR);
        vm.prank(alice);
        venue.transfer(PRIV, bob, 5);
        vm.prank(alice);
        venue.transfer(FUND, bob, 5);
        assertEq(venue.balanceOf(PRIV, bob), 5);
        assertEq(venue.balanceOf(FUND, bob), 5);
    }

    function test_EntityZonePairingGates() public {
        venue.issue(ENTB, alice, 50);
        _grantAttest(alice, entT);
        _grantAttest(bob, entR);
        vm.prank(alice);
        venue.transfer(ENTB, bob, 20);
        assertEq(venue.balanceOf(ENTB, bob), 20);
    }

    // ---------- issuance / operator powers ----------

    function test_IssueIsOperatorOnlyAndSessionless() public {
        vm.prank(alice);
        vm.expectRevert("Venue: not operator");
        venue.issue(FUND, alice, 1);
        // minted holder receives WITHOUT any session (admin distribution exemption, D12)…
        venue.issue(FUND, bob, 25);
        assertEq(venue.balanceOf(FUND, bob), 25);
        assertEq(venue.totalIssued(FUND), 25);
        // …but cannot transfer OUT without one
        vm.prank(bob);
        vm.expectRevert("Venue: sender not compliant");
        venue.transfer(FUND, alice, 1);
    }

    function test_RetireForcedBurn() public {
        venue.issue(FUND, alice, 100);
        venue.retire(FUND, alice, 40, "redemption");
        assertEq(venue.balanceOf(FUND, alice), 60);
        assertEq(venue.totalIssued(FUND), 60);
    }

    function test_OperatorTransferDestinationConstrained() public {
        venue.issue(FUND, alice, 100);
        // to an arbitrary ineligible address: refused
        vm.expectRevert("Venue: destination not compliant");
        venue.operatorTransfer(FUND, alice, bob, 10, "court order");
        // to a registered compliance escrow: allowed
        venue.registerEscrow(address(0xE5C0));
        venue.operatorTransfer(FUND, alice, address(0xE5C0), 10, "court order");
        assertEq(venue.balanceOf(FUND, address(0xE5C0)), 10);
        // to a receiving-session holder: allowed
        _grantAttest(bob, genR);
        venue.operatorTransfer(FUND, alice, bob, 5, "recovery");
        assertEq(venue.balanceOf(FUND, bob), 5);
    }

    // ---------- re-zoning / fail-closed ----------

    function test_RezoneTakesEffectImmediately() public {
        venue.issue(FUND, alice, 100);
        _grantAttest(alice, genT);
        _grantAttest(bob, genR);
        vm.prank(alice);
        venue.transfer(FUND, bob, 5); // passes under general
        venue.rezoneAsset(FUND, ZONE_REGD, "reclassified as Reg D");
        vm.prank(alice);
        vm.expectRevert("Venue: sender not compliant"); // general sessions no longer match
        venue.transfer(FUND, bob, 5);
    }

    function test_UnknownAssetFailsClosed() public {
        vm.prank(alice);
        vm.expectRevert("Venue: unknown asset");
        venue.transfer(keccak256("ghost"), bob, 1);
    }

    function test_PreflightMirrorsGates() public {
        venue.issue(FUND, alice, 10);
        (bool s0, bool r0) = venue.preflight(FUND, alice, bob);
        assertFalse(s0); assertFalse(r0);
        _grantAttest(alice, genT);
        _grantAttest(bob, genR);
        (bool s1, bool r1) = venue.preflight(FUND, alice, bob);
        assertTrue(s1); assertTrue(r1);
    }

    /// @dev Regimes must exist in the shared registry before an anchor can adopt them (Oct 2026
    ///      review, §5.3). This seeds the ones this suite uses; the ids are the same strings the
    ///      `GapLib.regimeHash` calls derive from, so the hashes match by construction.
    function _regimeRegistryWith(string[3] memory ids) internal returns (address) {
        RegimeRegistry r = new RegimeRegistry(0, address(0));
        for (uint256 i = 0; i < ids.length; i++) {
            r.proposeRegime(ids[i], 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, ids[i], "", 4);
        }
        return address(r);
    }
}
