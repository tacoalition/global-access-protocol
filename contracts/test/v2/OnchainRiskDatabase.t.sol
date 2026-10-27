// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../../src/v2/OnchainRiskDatabase.sol";

/**
 * @notice GAP-H1 acceptance tests: the ORDB's indexed Merkle tree gives every key its own
 *         allocation slot, so low-bit-colliding pseudonyms flag/unflag independently and a
 *         flagged key can never obtain a non-membership witness. Also exercises the
 *         adversarial hint paths from the design audit (dead/wrong predecessors, key 0).
 */
contract OnchainRiskDatabaseTest is Test {
    uint256 constant DEPTH = 8;
    uint256 constant FLAG_A = 1 << 0;
    uint256 constant FLAG_B = 1 << 3;

    OnchainRiskDatabase ordb;

    // k1 and k2 share their low `DEPTH` bits: the collision the old low-bit tree could not hold.
    bytes32 constant K1 = bytes32(uint256(0x1AB));
    bytes32 constant K2 = bytes32(uint256(0x2AB));

    function setUp() public {
        address poseidon = _deployPoseidon();
        ordb = new OnchainRiskDatabase(
            address(this), address(this), address(this), address(0xBEEF),
            poseidon, DEPTH, 1, 2, bytes32(uint256(0xdead))
        );
    }

    function _deployPoseidon() internal returns (address addr) {
        string[] memory lines = vm.split(vm.readFile("bytecode/Poseidon2.bytecode"), "\n");
        uint256 i = lines.length;
        while (i > 0 && bytes(lines[i - 1]).length == 0) i--;
        bytes memory code = vm.parseBytes(lines[i - 1]);
        assembly {
            addr := create(0, add(code, 0x20), mload(code))
        }
        require(addr != address(0), "poseidon deploy failed");
    }

    // ---- acceptance: colliding keys are independent ----

    function test_CollidingKeysFlagIndependently() public {
        bytes32 rootBefore = ordb.root();
        ordb.flagPseudonym(K1, FLAG_A);
        ordb.flagPseudonym(K2, FLAG_B); // old tree: "ORDB: index collision", must NOT revert now
        assertTrue(ordb.isFlagged(K1));
        assertTrue(ordb.isFlagged(K2));
        assertTrue(ordb.root() != rootBefore);
    }

    function test_UnflagOneCollidingKeyLeavesOtherFlagged() public {
        ordb.flagPseudonym(K1, FLAG_A);
        ordb.flagPseudonym(K2, FLAG_B);
        ordb.proposeUnflag(K1, FLAG_A);
        ordb.unflagPseudonym(K1, FLAG_A);
        assertFalse(ordb.isFlagged(K1));
        assertTrue(ordb.isFlagged(K2));

        // K1 is clean again: its witness is the genesis low leaf bracketing it below K2.
        (, bytes32 lowKey, bytes32 nextKey,,) = ordb.getNonMembershipWitness(K1);
        assertEq(lowKey, bytes32(0));
        assertEq(nextKey, K2);
    }

    function test_FlaggedKeyHasNoWitness() public {
        ordb.flagPseudonym(K1, FLAG_A);
        vm.expectRevert("ORDB: pseudonym flagged");
        ordb.getNonMembershipWitness(K1);
    }

    function test_CleanKeyWitnessBracketsBetweenFlags() public {
        ordb.flagPseudonym(K1, FLAG_A); // 0x1AB
        ordb.flagPseudonym(K2, FLAG_B); // 0x2AB
        (, bytes32 lowKey, bytes32 nextKey,,) = ordb.getNonMembershipWitness(bytes32(uint256(0x200)));
        assertEq(lowKey, K1);
        assertEq(nextKey, K2);
        (, lowKey, nextKey,,) = ordb.getNonMembershipWitness(bytes32(uint256(0x300)));
        assertEq(lowKey, K2);
        assertEq(nextKey, bytes32(0)); // tail
    }

    // ---- repeated flags only touch the mapping, not the tree ----

    function test_ReflagSameKeyKeepsRoot() public {
        ordb.flagPseudonym(K1, FLAG_A);
        bytes32 root1 = ordb.root();
        ordb.flagPseudonym(K1, FLAG_B);
        assertEq(ordb.getFlags(K1), FLAG_A | FLAG_B);
        assertEq(ordb.root(), root1);
    }

    // ---- adversarial hints (design-audit findings) ----

    function test_InsertWithDeadPredecessorReverts() public {
        ordb.flagPseudonym(bytes32(uint256(100)), FLAG_A); // slot 1
        ordb.flagPseudonym(bytes32(uint256(300)), FLAG_A); // slot 2
        ordb.proposeUnflag(bytes32(uint256(300)), FLAG_A);
        ordb.unflagPseudonym(bytes32(uint256(300)), FLAG_A); // slot 2 freed (dead)
        vm.expectRevert("IMT: dead predecessor");
        ordb.flagPseudonym(bytes32(uint256(200)), FLAG_A, 2);
    }

    function test_InsertWithStalePredecessorReverts() public {
        ordb.flagPseudonym(bytes32(uint256(100)), FLAG_A);
        // genesis is no longer 200's predecessor (its nextKey is 100 < 200)
        vm.expectRevert("IMT: bad predecessor");
        ordb.flagPseudonym(bytes32(uint256(200)), FLAG_A, 0);
    }

    function test_UnflagWithWrongPredecessorReverts() public {
        ordb.flagPseudonym(bytes32(uint256(100)), FLAG_A); // slot 1
        ordb.flagPseudonym(bytes32(uint256(200)), FLAG_A); // slot 2
        // genesis.nextKey == 100 != 200, removing the tail via genesis must fail
        ordb.proposeUnflag(bytes32(uint256(200)), FLAG_A);   // appeal raised, so the gate is open
        vm.expectRevert("IMT: bad predecessor");               // and the TREE is what refuses
        ordb.unflagPseudonym(bytes32(uint256(200)), FLAG_A, 0);
    }

    function test_SlotReuseKeepsListCoherent() public {
        ordb.flagPseudonym(bytes32(uint256(100)), FLAG_A); // slot 1
        ordb.flagPseudonym(bytes32(uint256(300)), FLAG_A); // slot 2
        ordb.proposeUnflag(bytes32(uint256(100)), FLAG_A);
        ordb.unflagPseudonym(bytes32(uint256(100)), FLAG_A); // frees slot 1
        ordb.flagPseudonym(bytes32(uint256(200)), FLAG_A);   // reuses slot 1
        (, bytes32 lowKey, bytes32 nextKey,,) = ordb.getNonMembershipWitness(bytes32(uint256(250)));
        assertEq(lowKey, bytes32(uint256(200)));
        assertEq(nextKey, bytes32(uint256(300)));
        (, lowKey, nextKey,,) = ordb.getNonMembershipWitness(bytes32(uint256(150)));
        assertEq(lowKey, bytes32(0)); // 100 was removed, genesis brackets below 200
        assertEq(nextKey, bytes32(uint256(200)));
    }

    // ---- key-0 / genesis protection ----

    function test_FlagKeyZeroReverts() public {
        vm.expectRevert("ORDB: bad key");
        ordb.flagPseudonym(bytes32(0), FLAG_A);
    }

    function test_FlagContractZeroAddressReverts() public {
        vm.expectRevert("ORDB: zero addr");
        ordb.flagContract(address(0), FLAG_A);
    }

    function test_UnflagKeyZeroReverts() public {
        // The appeal gate answers first now, and it is the right answer: no monitor can raise an
        // appeal for a key that can never be flagged, so there is nothing for governance to clear.
        vm.expectRevert("ORDB: no appeal raised");
        ordb.unflagPseudonym(bytes32(0), FLAG_A);
    }

    function test_NonFieldKeyReverts() public {
        bytes32 overP = bytes32(GapLib.P);
        vm.expectRevert("ORDB: bad key");
        ordb.flagPseudonym(overP, FLAG_A);
    }

    // ---- witness integrity: the returned path must recompute the returned root ----

    function test_WitnessPathRecomputesRoot() public {
        ordb.flagPseudonym(K1, FLAG_A);
        ordb.flagPseudonym(K2, FLAG_B);
        (uint256 lowIndex, bytes32 lowKey, bytes32 nextKey, bytes32[] memory siblings, bytes32 root_) =
            ordb.getNonMembershipWitness(bytes32(uint256(0x200)));
        assertEq(root_, ordb.root());
        IPoseidon2 h = IPoseidon2(ordb.poseidon());
        bytes32 node = h.poseidon([lowKey, nextKey]);
        uint256 idx = lowIndex;
        for (uint256 level = 0; level < DEPTH; level++) {
            node = idx & 1 == 0 ? h.poseidon([node, siblings[level]]) : h.poseidon([siblings[level], node]);
            idx >>= 1;
        }
        assertEq(node, root_, "sibling path must fold to the root");
    }

    // ---- offchain parity: pinned roots computed by the JS IndexedTree mirror ----
    // (circuits/scripts/v2/gap_crypto.js, genesis init, then flag 100, flag 300,
    //  unflag 100, flag 200 at depth 8; regenerate with the one-liner in the PR notes)

    function test_RootParityWithJsMirror() public {
        assertEq(
            ordb.root(),
            bytes32(0x1d2377d86b43f7d6ff324c8c5f693fe6b5005f7d60bbbbde8161d79d11a35e85),
            "genesis-only root must match the JS mirror"
        );
        ordb.flagPseudonym(bytes32(uint256(100)), FLAG_A);
        ordb.flagPseudonym(bytes32(uint256(300)), FLAG_A);
        ordb.proposeUnflag(bytes32(uint256(100)), FLAG_A);
        ordb.unflagPseudonym(bytes32(uint256(100)), FLAG_A);
        ordb.flagPseudonym(bytes32(uint256(200)), FLAG_A);
        assertEq(
            ordb.root(),
            bytes32(0x16cb7b4b4b4b94b11aa152057439c452d84355e0734b1db89527cb65869723bf),
            "insert/remove/free-slot-reuse sequence must match the JS mirror"
        );
    }

    // ---- capacity ----

    function test_TreeFullReverts() public {
        // depth 8 → 256 slots, slot 0 is genesis → 255 insertable keys
        for (uint256 i = 1; i <= 255; i++) {
            ordb.flagPseudonym(bytes32(i), FLAG_A);
        }
        vm.expectRevert("IMT: full");
        ordb.flagPseudonym(bytes32(uint256(1000)), FLAG_A);
    }

    // ---------- the appeal path: TM proposes, governance disposes (Oct 2026 review, §5.4) ----------

    /**
     * The DSI paper's remedy for a false positive is an appeal to the monitor. Ours keeps the
     * flag/clear split: a role that can do both can be leaned on to quietly undo a flag, but the
     * appeal now has an on-chain expression instead of happening entirely in private.
     */
    function test_GovernanceCannotClearAFlagNoMonitorAppealed() public {
        ordb.flagPseudonym(K1, FLAG_A);
        vm.expectRevert("ORDB: no appeal raised");
        ordb.unflagPseudonym(K1, FLAG_A);
        assertTrue(ordb.isFlagged(K1), "a flag with no appeal behind it stands");
    }

    /// An appeal is for specific flags, and does not become a licence to clear the rest.
    function test_AnAppealDoesNotCoverFlagsItDidNotName() public {
        ordb.flagPseudonym(K1, FLAG_A);
        ordb.flagPseudonym(K1, FLAG_B);
        ordb.proposeUnflag(K1, FLAG_A);
        vm.expectRevert("ORDB: appeal does not cover these flags");
        ordb.unflagPseudonym(K1, FLAG_A | FLAG_B);
        ordb.unflagPseudonym(K1, FLAG_A);           // what WAS appealed clears
        assertTrue(ordb.isFlagged(K1), "the un-appealed flag survives");
    }

    /// One appeal, one clearing. A consumed appeal is not a standing permission.
    function test_AnAppealIsConsumedAndCannotBeReused() public {
        ordb.flagPseudonym(K1, FLAG_A);
        ordb.proposeUnflag(K1, FLAG_A);
        assertEq(ordb.unflagProposalOf(K1), FLAG_A, "the appeal is visible while it stands");
        ordb.unflagPseudonym(K1, FLAG_A);
        assertEq(ordb.unflagProposalOf(K1), 0, "and is spent once acted on");

        ordb.flagPseudonym(K1, FLAG_A);             // flagged again
        vm.expectRevert("ORDB: no appeal raised");
        ordb.unflagPseudonym(K1, FLAG_A);
    }

    /// A monitor that changes its mind can withdraw before governance acts.
    function test_AMonitorCanWithdrawAnAppeal() public {
        ordb.flagPseudonym(K1, FLAG_A);
        ordb.proposeUnflag(K1, FLAG_A);
        ordb.withdrawUnflagProposal(K1);
        vm.expectRevert("ORDB: no appeal raised");
        ordb.unflagPseudonym(K1, FLAG_A);
    }

    /// And an appeal cannot be raised for something that was never flagged.
    function test_NoAppealForACleanPseudonym() public {
        vm.expectRevert("ORDB: not flagged");
        ordb.proposeUnflag(K1, FLAG_A);
    }
}
