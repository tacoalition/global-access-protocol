// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "../../src/v2/RegimeRegistry.sol";
import "forge-std/Test.sol";
import "../../src/v2/IdentityAnchor.sol";
import "../../src/v2/libraries/GapLib.sol";

/**
 * @notice GAP-H4 acceptance: revoking an IK invalidates every credential it issued: the first
 *         batch atomically inside revokeIK, the rest via the permissionless bounded purge, and
 *         holders can be re-credentialed by another IK afterwards. Also pins the tombstone rule
 *         (a revoked IK's name can never be re-registered).
 */
contract IdentityAnchorTest is Test {
    IdentityAnchor ita;
    bytes32 regime;
    bytes32 ikA;
    bytes32 ikB;
    address ikAKey = address(0xA11CE);
    address ikBKey = address(0xB0B);

    /// The shared regime registry this suite's anchors adopt from (Oct 2026 review, §5.3).
    address internal _regimes;

    function setUp() public {
        address poseidon = _deployPoseidon();
        string[1] memory _ids;
        _ids[0] = "standard-identity";
        _regimes = _regimeRegistryWith(_ids);
        ita = new IdentityAnchor(address(this), poseidon, 10, _regimes);
        regime = GapLib.regimeHash("standard-identity", 1, 0, 0);
        ita.adoptRegime(regime);
        bytes32[] memory regimes = new bytes32[](1);
        regimes[0] = regime;
        address[] memory aKeys = new address[](1); aKeys[0] = ikAKey;
        address[] memory bKeys = new address[](1); bKeys[0] = ikBKey;
        ikA = ita.registerIK("ik-a", aKeys, address(0), hex"01", regimes, "");
        ikB = ita.registerIK("ik-b", bKeys, address(0), hex"02", regimes, "");
    }

    function _deployPoseidon() internal returns (address addr) {
        string[] memory lines = vm.split(vm.readFile("bytecode/Poseidon2.bytecode"), "\n");
        uint256 i = lines.length;
        while (i > 0 && bytes(lines[i - 1]).length == 0) i--;
        bytes memory code = vm.parseBytes(lines[i - 1]);
        assembly { addr := create(0, add(code, 0x20), mload(code)) }
        require(addr != address(0), "poseidon deploy failed");
    }

    function _issue(bytes32 ikId, address key, uint256 did) internal {
        vm.prank(key);
        ita.issueCredential(regime, bytes32(did), bytes32(uint256(0xC0FFEE00 + did)), 0, ikId, bytes32(0));
    }

    // ---- acceptance: revokeIK invalidates issued credentials ----

    function test_RevokeIKPurgesFirstBatchAtomically() public {
        for (uint256 d = 1; d <= 5; d++) _issue(ikA, ikAKey, d);
        bytes32 rootBefore = ita.getAttributeRegimeRoot(regime);
        ita.revokeIK(ikA); // 5 <= REVOKE_PURGE_BATCH → fully purged in one tx
        (uint256 processed, uint256 total) = ita.purgeStatus(ikA);
        assertEq(processed, 5);
        assertEq(total, 5);
        for (uint256 d = 1; d <= 5; d++) {
            assertFalse(ita.isCredentialValid(regime, bytes32(d)));
        }
        assertTrue(ita.getAttributeRegimeRoot(regime) != rootBefore, "leaves must be zeroed");
    }

    function test_LargePurgeContinuesPermissionlessly() public {
        for (uint256 d = 1; d <= 20; d++) _issue(ikA, ikAKey, d);
        ita.revokeIK(ikA); // purges REVOKE_PURGE_BATCH = 16
        (uint256 processed, uint256 total) = ita.purgeStatus(ikA);
        assertEq(processed, 16);
        assertEq(total, 20);
        assertTrue(ita.isCredentialValid(regime, bytes32(uint256(20)))); // tail still live, window
        vm.prank(address(0xDEAD)); // anyone may drive the purge
        ita.purgeRevokedIKCredentials(ikA, 10);
        (processed,) = ita.purgeStatus(ikA);
        assertEq(processed, 20);
        for (uint256 d = 1; d <= 20; d++) {
            assertFalse(ita.isCredentialValid(regime, bytes32(d)));
        }
    }

    function test_PurgeRequiresRevokedIK() public {
        _issue(ikA, ikAKey, 1);
        vm.expectRevert("ITA: ik not revoked");
        ita.purgeRevokedIKCredentials(ikA, 10);
    }

    function test_RevokedIKCannotIssue() public {
        ita.revokeIK(ikA);
        vm.prank(ikAKey);
        vm.expectRevert("ITA: ik invalid");
        ita.issueCredential(regime, bytes32(uint256(1)), bytes32(uint256(1)), 0, ikA, bytes32(0));
    }

    function test_DoubleRevokeReverts() public {
        ita.revokeIK(ikA);
        vm.expectRevert("ITA: already revoked");
        ita.revokeIK(ikA);
    }

    // ---- tombstone: a revoked IK's name (== ikId) can never come back ----

    function test_RevokedIKNameCannotReRegister() public {
        ita.revokeIK(ikA);
        address[] memory keys = new address[](1); keys[0] = address(0xEEE);
        bytes32[] memory regimes = new bytes32[](1); regimes[0] = regime;
        vm.expectRevert("ITA: ik exists");
        ita.registerIK("ik-a", keys, address(0), hex"03", regimes, "");
    }

    // ---- liveness: holders can be re-credentialed after their issuer is revoked ----

    function test_ReissueAfterIKRevocationByAnotherIK() public {
        _issue(ikA, ikAKey, 7);
        ita.revokeIK(ikA);
        assertFalse(ita.isCredentialValid(regime, bytes32(uint256(7))));
        _issue(ikB, ikBKey, 7); // re-issue over the revoked record
        assertTrue(ita.isCredentialValid(regime, bytes32(uint256(7))));
        assertEq(ita.getCredential(regime, bytes32(uint256(7))).issuerIKId, ikB);
    }

    /// A stale purge ref from a revoked IK must NOT kill a credential re-issued by another IK.
    function test_PurgeSkipsReissuedCredentials() public {
        for (uint256 d = 1; d <= 20; d++) _issue(ikA, ikAKey, d);
        ita.revokeIK(ikA);                                     // purges dids 1..16; 17..20 pending
        ita.revokeCredential(regime, bytes32(uint256(17)), "holder switches issuer"); // admin revoke
        _issue(ikB, ikBKey, 17);                               // holder 17 re-credentialed by ikB
        ita.purgeRevokedIKCredentials(ikA, 10);                // stale ref for 17, must skip it
        assertTrue(ita.isCredentialValid(regime, bytes32(uint256(17))), "reissued credential must survive");
        assertEq(ita.getCredential(regime, bytes32(uint256(17))).issuerIKId, ikB);
        assertFalse(ita.isCredentialValid(regime, bytes32(uint256(18))));
    }

    function test_ActiveCredentialCannotBeDoubleIssued() public {
        _issue(ikA, ikAKey, 3);
        vm.prank(ikBKey);
        vm.expectRevert("ITA: credential exists");
        ita.issueCredential(regime, bytes32(uint256(3)), bytes32(uint256(0xF00)), 0, ikB, bytes32(0));
    }

    /// @dev Regimes must exist in the shared registry before an anchor can adopt them (Oct 2026
    ///      review, §5.3). This seeds the ones this suite uses; the ids are the same strings the
    ///      `GapLib.regimeHash` calls derive from, so the hashes match by construction.
    function _regimeRegistryWith(string[1] memory ids) internal returns (address) {
        RegimeRegistry r = new RegimeRegistry(0, address(0));
        for (uint256 i = 0; i < ids.length; i++) {
            r.proposeRegime(ids[i], 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, ids[i], "", 4);
        }
        return address(r);
    }

    // ---------- the regime registry is enforced (Oct 2026 review, §5.3) ----------

    /**
     * The white paper (§3.3, §4.2) describes the Regime Registry as the shared semantic backbone
     * anchors consult. It used to be advisory-only, its own header said nothing load-bearing read
     * it, which meant an anchor could invent a regime and issue under it. "Attribute index 2 means
     * citizenship" is only a shared fact if something enforces where the regime came from.
     */
    function test_AnAnchorCannotAdoptARegimeTheRegistryHasNeverHeardOf() public {
        bytes32 invented = GapLib.regimeHash("regime-i-just-made-up", 1, 0, 0);
        vm.expectRevert("ITA: regime not registered");
        ita.adoptRegime(invented);
    }

    /// And a registered one is adopted exactly as before, the gate adds a precondition, not a change
    /// of behaviour.
    function test_ARegisteredRegimeStillAdopts() public {
        RegimeRegistry(_regimes).proposeRegime(
            "late-arriving-regime", 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, "Late", "", 4
        );
        bytes32 rh = GapLib.regimeHash("late-arriving-regime", 1, 0, 0);
        ita.adoptRegime(rh);
        assertTrue(ita.supportedRegimes(rh), "a registered regime adopts");
    }

    /// An anchor with no registry at all is refused at construction: that is the state this replaced.
    function test_AnAnchorCannotBeBuiltWithoutARegistry() public {
        vm.expectRevert("ITA: regime registry");
        // Any non-zero poseidon will do: the registry check is a constructor require, reached
        // before the hash is ever called, and _deployPoseidon() cannot run twice in one test.
        new IdentityAnchor(address(this), address(0xBEEF), 10, address(0));
    }
}
