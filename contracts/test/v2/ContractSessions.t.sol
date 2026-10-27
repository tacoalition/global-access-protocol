// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "./GapDexFixture.sol";

/// An anchor anyone can deploy: it says yes to every CC-control and regime question, so
/// `ClassificationContract` will record a certification from it for any target.
contract AnyoneAnchor {
    function isCCControl(bytes32, address) external pure returns (bool) { return true; }
    function isCCAuthorizedForRegime(bytes32, bytes32) external pure returns (bool) { return true; }
}

/**
 * Contract Sessions are a permissionless, capped index. Both ways that index used to lock a real
 * certifier out, each a regression test here:
 *   1. a stranger filled the target's one list with sixteen certifications from their own anchor;
 *   2. the documented renewal flow (revoke, certify a new index) filled it after sixteen renewals.
 */
contract ContractSessionsTest is GapDexFixture {
    function _certify(address anchor, uint256 class) internal returns (uint256) {
        return clsStore.addClassification(
            address(dex), anchor, secRegime, class, ccId, keccak256("dex-audit"), address(this), "", true
        );
    }

    function _requirement() internal view returns (SessionManager.ContractRequirement memory) {
        address[] memory ctas = new address[](1);
        ctas[0] = address(cta);
        return SessionManager.ContractRequirement(secRegime, DEX_CLASS, ctas, 30 days, true, true);
    }

    function test_strangerFillingTheirOwnAnchorsListDoesNotLockOutTheRealCertifier() public {
        vm.startPrank(mallory);
        AnyoneAnchor fake = new AnyoneAnchor();
        for (uint256 i = 0; i < sm.MAX_CONTRACT_SESSIONS(); i++) {
            // `class` varies only to get past the store's duplicate check
            sm.registerContractSession(address(dex), _certify(address(fake), 1000 + i));
        }
        uint256 seventeenth = _certify(address(fake), 999);
        vm.expectRevert(bytes("SM: too many contract sessions"));
        sm.registerContractSession(address(dex), seventeenth);
        vm.stopPrank();

        assertEq(sm.contractSessionCount(address(dex), address(fake)), sm.MAX_CONTRACT_SESSIONS());
        assertEq(sm.contractSessionCount(address(dex), address(cta)), 0);

        sm.registerContractSession(address(dex), _certify(address(cta), DEX_CLASS));
        assertTrue(sm.hasValidContractSession(address(dex), _requirement()));
    }

    function test_strangersAnchorNeverSatisfiesAVenueThatDoesNotAcceptIt() public {
        vm.startPrank(mallory);
        AnyoneAnchor fake = new AnyoneAnchor();
        sm.registerContractSession(address(dex), _certify(address(fake), DEX_CLASS));
        vm.stopPrank();
        assertFalse(sm.hasValidContractSession(address(dex), _requirement()));
    }

    function test_renewalsBeyondTheCapStillRegister() public {
        uint256 renewals = sm.MAX_CONTRACT_SESSIONS() * 2;
        for (uint256 i = 0; i < renewals; i++) {
            uint256 idx = _certify(address(cta), DEX_CLASS);
            sm.registerContractSession(address(dex), idx);
            assertTrue(sm.hasValidContractSession(address(dex), _requirement()));
            clsStore.revokeClassification(address(dex), idx); // renewal: revoke old, certify new
            assertFalse(sm.hasValidContractSession(address(dex), _requirement()));
        }
        sm.registerContractSession(address(dex), _certify(address(cta), DEX_CLASS));
        assertTrue(sm.hasValidContractSession(address(dex), _requirement()));
        assertLe(sm.contractSessionCount(address(dex), address(cta)), sm.MAX_CONTRACT_SESSIONS());
    }

    function test_liveEntriesAreNeverDroppedToMakeRoom() public {
        for (uint256 i = 0; i < sm.MAX_CONTRACT_SESSIONS(); i++) {
            sm.registerContractSession(address(dex), _certify(address(cta), 2000 + i));
        }
        uint256 extra = _certify(address(cta), DEX_CLASS);
        vm.expectRevert(bytes("SM: too many contract sessions"));
        sm.registerContractSession(address(dex), extra);
    }
}
