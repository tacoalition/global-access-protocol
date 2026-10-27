// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import {DIDRegistryV2} from "../../src/v2/DIDRegistryV2.sol";

/// Adversarial probes on allocation-ordered slots. Not a feature suite: these are the ways the
/// change could be wrong that the happy path would never show.
contract AllocPressureTest is Test {
    DIDRegistryV2 internal reg;
    address internal constant A = address(0xA11CE);

    function setUp() public {
        string[] memory lines = vm.split(vm.readFile("bytecode/Poseidon2.bytecode"), "\n");
        uint256 i = lines.length;
        while (i > 0 && bytes(lines[i - 1]).length == 0) i--;
        bytes memory code = vm.parseBytes(lines[i - 1]);
        address p;
        assembly { p := create(0, add(code, 0x20), mload(code)) }
        reg = new DIDRegistryV2(p, 4, 0, address(0));   // depth 4 = 16 slots, so "full" is reachable
    }

    function _reg(bytes32 did, address who) internal {
        address[] memory k = new address[](1);
        k[0] = who;
        bytes32 c = reg.registrationCommitment(did, keccak256("s"), bytes32(0), k, who);
        vm.prank(who); reg.commitRegistration(c);
        vm.roll(block.number + 1);
        vm.prank(who); reg.registerDID(did, keccak256("s"), bytes32(0), k);
    }

    /// PROBE 1: a tree that genuinely fills must say so, not corrupt or silently wrap.
    function test_AFullTreeRefusesRatherThanWrapping() public {
        for (uint256 i = 0; i < 16; i++) {
            _reg(bytes32(uint256(0x1000 + i * 7919)), address(uint160(0x100 + i)));
        }
        // Commit phase first, so expectRevert binds to the reveal and not to the commitment.
        bytes32 extra = bytes32(uint256(0xDEAD));
        address who = address(0xFEED);
        address[] memory k = new address[](1); k[0] = who;
        bytes32 c = reg.registrationCommitment(extra, keccak256("s"), bytes32(0), k, who);
        vm.prank(who); reg.commitRegistration(c);
        vm.roll(block.number + 1);
        vm.prank(who);
        vm.expectRevert("SMT: tree full");
        reg.registerDID(extra, keccak256("s"), bytes32(0), k);
    }

    /// PROBE 2: slot 0 is a real slot, not confused with "unallocated" by the +1 offset.
    function test_SlotZeroIsUsableAndDistinctFromUnallocated() public {
        bytes32 first = bytes32(uint256(0xAAAA));
        _reg(first, A);
        (, uint256 idx) = reg.getMerkleProof(first);
        assertEq(idx, 0, "the first registrant really is in slot 0");
        // and an unregistered DID is refused rather than handed slot 0's proof
        vm.expectRevert("DID: not in tree");
        reg.getMerkleProof(bytes32(uint256(0xBBBB)));
    }

    /// PROBE 3: the OLD behaviour would have answered this with a plausible-looking proof for a slot
    /// the DID never occupied. That is the quiet failure allocation-ordering removes.
    function test_AnUnregisteredDidGetsNoProofAtAll() public {
        _reg(bytes32(uint256(0xAAAA)), A);
        bytes32 neverRegistered = bytes32(uint256(0xAAAA) ^ (uint256(1) << 90));
        vm.expectRevert("DID: not in tree");
        reg.getMerkleProof(neverRegistered);
    }

    /// PROBE 4: re-registering a DID must not consume a second slot.
    function test_ARegisteredDidCannotBeRegisteredAgain() public {
        bytes32 did = bytes32(uint256(0xAAAA));
        _reg(did, A);
        address[] memory k = new address[](1); k[0] = A;
        bytes32 c = reg.registrationCommitment(did, keccak256("s"), bytes32(0), k, A);
        vm.prank(A); reg.commitRegistration(c);
        vm.roll(block.number + 1);
        vm.prank(A);
        vm.expectRevert("DID: exists");
        reg.registerDID(did, keccak256("s"), bytes32(0), k);
    }
}
