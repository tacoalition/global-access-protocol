// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../../src/v2/DIDSuccessionRegistry.sol";

/**
 * @notice S6 acceptance: a holder's identity can be SUCCEEDED without the chain learning which
 *         identity succeeded which. The registry holds one opaque commitment per supersession: 
 *         no plaintext DID pair in storage, in calldata or in an event, and the three properties
 *         a recovery lane depends on are pinned here: only an authorized writer may commit, a
 *         replayed supersession is idempotent rather than doubled, and the commitment is the
 *         `GAP_DID_SUPERSESSION_V1` fold the off-chain ladder computes (one shared vector, also
 *         asserted by `services/gap-ik-api/test/succession-commitment.test.ts`).
 */
contract DIDSuccessionRegistryTest is Test {
    DIDSuccessionRegistry registry;

    address ikWriter = address(0x1D);
    address stranger = address(0x5A);

    // The shared parity vector. Both mirrors of the fold assert THIS literal, so a change to
    // either side (domain tag, field order, encoding) fails on one side and is caught.
    bytes32 constant OLD_DID = keccak256("gap-succession-test-old-did");
    bytes32 constant NEW_DID = keccak256("gap-succession-test-new-did");
    bytes32 constant NONCE = bytes32(uint256(7));
    bytes32 constant PINNED_COMMITMENT =
        0xb1c798431d6f21d34e137caa12e558d6f231c3d0caf1301dd9ebe030170da3ac;

    event SuccessionCommitted(bytes32 indexed commitment, address indexed writer);

    function setUp() public {
        registry = new DIDSuccessionRegistry(address(this), ikWriter);
    }

    function _fold(bytes32 oldDid, bytes32 newDid, bytes32 nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(registry.SUPERSESSION_DOMAIN(), oldDid, newDid, nonce));
    }

    // ---- authorization ----

    function test_UnauthorizedSuccessionWriteReverts() public {
        // Folded BEFORE the expectation is armed: `_fold` reads the domain off the registry, and
        // that read would otherwise be the "next call" the cheatcode is watching.
        bytes32 commitment = _fold(OLD_DID, NEW_DID, NONCE);
        vm.prank(stranger);
        vm.expectRevert("DSR: not succession writer");
        registry.commitSuccession(commitment);
    }

    function test_OnlyOwnerMayAuthorizeAWriter() public {
        vm.prank(stranger);
        vm.expectRevert("DSR: not owner");
        registry.setWriter(stranger, true);
    }

    function test_RevokedWriterCanNoLongerCommit() public {
        bytes32 commitment = _fold(OLD_DID, NEW_DID, NONCE);
        registry.setWriter(ikWriter, false);
        vm.prank(ikWriter);
        vm.expectRevert("DSR: not succession writer");
        registry.commitSuccession(commitment);
    }

    // ---- idempotence ----

    function test_ReplayedSupersessionIsIdempotentNotDoubled() public {
        bytes32 commitment = _fold(OLD_DID, NEW_DID, NONCE);
        vm.prank(ikWriter);
        assertTrue(registry.commitSuccession(commitment));
        uint64 firstAt = registry.committedAt(commitment);

        vm.warp(block.timestamp + 1000);
        vm.recordLogs();
        vm.prank(ikWriter);
        assertFalse(registry.commitSuccession(commitment));

        // Not doubled anywhere a reader could see it: no second event, no second count, and the
        // ORIGINAL timestamp stands (a replay must not rewrite when the supersession happened).
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(registry.successionCount(), 1);
        assertEq(registry.committedAt(commitment), firstAt);
        assertEq(registry.committedBy(commitment), ikWriter);
    }

    function test_ZeroCommitmentIsRefused() public {
        vm.prank(ikWriter);
        vm.expectRevert("DSR: zero commitment");
        registry.commitSuccession(bytes32(0));
    }

    // ---- no public linkage ----

    function test_EventCarriesNeitherDidOfThePair() public {
        bytes32 commitment = _fold(OLD_DID, NEW_DID, NONCE);
        vm.recordLogs();
        vm.prank(ikWriter);
        registry.commitSuccession(commitment);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        for (uint256 i = 0; i < logs[0].topics.length; i++) {
            assertTrue(logs[0].topics[i] != OLD_DID, "old DID leaked in a topic");
            assertTrue(logs[0].topics[i] != NEW_DID, "new DID leaked in a topic");
        }
        // The data half too: no 32-byte word of it may be either DID.
        bytes memory data = logs[0].data;
        for (uint256 offset = 0; offset + 32 <= data.length; offset += 32) {
            bytes32 word;
            assembly { word := mload(add(add(data, 32), offset)) }
            assertTrue(word != OLD_DID, "old DID leaked in event data");
            assertTrue(word != NEW_DID, "new DID leaked in event data");
        }
    }

    function test_UnknownCommitmentIsSimplyUnknown() public view {
        bytes32 never = _fold(OLD_DID, NEW_DID, bytes32(uint256(999)));
        assertFalse(registry.isCommitted(never));
        assertEq(registry.committedAt(never), 0);
        assertEq(registry.committedBy(never), address(0));
    }

    // ---- the GAP_DID_SUPERSESSION_V1 fold ----

    function test_CommitmentIsThePinnedSupersessionFold() public view {
        assertEq(registry.SUPERSESSION_DOMAIN(), keccak256("GAP_DID_SUPERSESSION_V1"));
        assertEq(_fold(OLD_DID, NEW_DID, NONCE), PINNED_COMMITMENT);
    }

    function test_ANewNonceIsANewCommitment() public view {
        assertTrue(_fold(OLD_DID, NEW_DID, NONCE) != _fold(OLD_DID, NEW_DID, bytes32(uint256(8))));
        // Direction matters: superseding A with B is not superseding B with A.
        assertTrue(_fold(OLD_DID, NEW_DID, NONCE) != _fold(NEW_DID, OLD_DID, NONCE));
    }
}
