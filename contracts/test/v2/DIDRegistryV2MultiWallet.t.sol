// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import {DIDRegistryV2} from "../../src/v2/DIDRegistryV2.sol";
import {PoseidonSparseTree} from "../../src/v2/libraries/PoseidonSparseTree.sol";
import {IPoseidon2} from "../../src/interfaces/IPoseidon2.sol";

/// @dev Test-only builder for the off-chain spending-key tree committed by DIDRegistryV2.
contract AssignedSlotSpendingTree {
    using PoseidonSparseTree for PoseidonSparseTree.Tree;

    PoseidonSparseTree.Tree private _tree;
    IPoseidon2 private immutable _poseidon;

    constructor(address poseidon, uint256 depth) {
        _poseidon = IPoseidon2(poseidon);
        _tree.init(poseidon, depth);
    }

    function assign(address wallet, uint256 slot) external returns (bytes32) {
        bytes32 key = bytes32(uint256(uint160(wallet)));
        _tree.set(slot, _poseidon.poseidon([key, bytes32(0)]));
        return _tree.root;
    }

    function isAssigned(address wallet, uint256 slot) external view returns (bool) {
        bytes32 key = bytes32(uint256(uint160(wallet)));
        return _tree.leafAt(slot) == _poseidon.poseidon([key, bytes32(0)]);
    }

    function root() external view returns (bytes32) {
        return _tree.root;
    }
}

/**
 * @notice Multi-wallet readiness at the DID boundary. Spending wallets are leaves in an assigned-
 *         slot tree; governance keys control only the committed root and remain a separate capped set.
 */
contract DIDRegistryV2MultiWalletTest is Test {
    bytes32 private constant DID = bytes32(uint256(0xD1D));
    bytes32 private constant SALT_COMMITMENT = bytes32(uint256(0x5A17));

    address private constant CONTROLLER = address(0xC011);
    address private constant WALLET_A = address(0x1001);
    address private constant WALLET_B = address(0x1101);
    uint256 private constant SLOT_A = 7;
    uint256 private constant SLOT_B = 201;

    DIDRegistryV2 private registry;
    AssignedSlotSpendingTree private spendingTree;

    function setUp() public {
        address poseidon = _deployPoseidon();
        registry = new DIDRegistryV2(poseidon, 10, 0, address(0));
        spendingTree = new AssignedSlotSpendingTree(poseidon, 8);
        assertEq(uint160(WALLET_A) & 0xff, uint160(WALLET_B) & 0xff, "wallet low bits must collide");
        assertTrue(SLOT_A != SLOT_B, "assigned slots must be distinct");
    }

    function test_TwoAssignedWalletSlotsRotateUnderStableController() public {
        bytes32 singleWalletRoot = spendingTree.assign(WALLET_A, SLOT_A);
        _register(singleWalletRoot, _keys(1));

        DIDRegistryV2.DIDEntry memory beforeUpdate = registry.getDID(DID);
        bytes32 didRootBefore = registry.root();
        bytes32 twoWalletRoot = spendingTree.assign(WALLET_B, SLOT_B);

        vm.prank(CONTROLLER);
        registry.updateSpendingKeyRoot(DID, twoWalletRoot);

        DIDRegistryV2.DIDEntry memory afterUpdate = registry.getDID(DID);
        assertTrue(spendingTree.isAssigned(WALLET_A, SLOT_A));
        assertTrue(spendingTree.isAssigned(WALLET_B, SLOT_B));
        assertTrue(singleWalletRoot != twoWalletRoot);
        assertEq(afterUpdate.spendingKeyRoot, twoWalletRoot);
        assertEq(afterUpdate.privateSaltCommitment, SALT_COMMITMENT);
        assertEq(afterUpdate.registeredAt, beforeUpdate.registeredAt);
        assertEq(afterUpdate.governanceKeys.length, 1);
        assertEq(afterUpdate.governanceKeys[0], CONTROLLER);
        assertTrue(registry.root() != didRootBefore);
        assertEq(registry.didCount(), 1);
    }

    function test_SpendingWalletsAreNotImplicitGovernanceKeys() public {
        spendingTree.assign(WALLET_A, SLOT_A);
        bytes32 twoWalletRoot = spendingTree.assign(WALLET_B, SLOT_B);
        _register(twoWalletRoot, _keys(1));

        DIDRegistryV2.DIDEntry memory entry = registry.getDID(DID);
        assertEq(entry.governanceKeys.length, 1);
        assertEq(entry.governanceKeys[0], CONTROLLER);
        assertTrue(entry.governanceKeys[0] != WALLET_A && entry.governanceKeys[0] != WALLET_B);

        vm.prank(WALLET_A);
        vm.expectRevert("DID: not governance key");
        registry.updateSpendingKeyRoot(DID, bytes32(uint256(0xA)));

        vm.prank(WALLET_B);
        vm.expectRevert("DID: not governance key");
        registry.updateSpendingKeyRoot(DID, bytes32(uint256(0xB)));

        assertEq(registry.getDID(DID).spendingKeyRoot, twoWalletRoot);
    }

    function test_GovernanceKeysAreCappedAtFiveAndSeparateFromWallets() public {
        spendingTree.assign(WALLET_A, SLOT_A);
        bytes32 twoWalletRoot = spendingTree.assign(WALLET_B, SLOT_B);

        _commitAs(CONTROLLER, twoWalletRoot, _keys(5));   // only the valid shape is committed
        vm.startPrank(CONTROLLER);
        vm.expectRevert("DID: keys 1..5");
        registry.registerDID(DID, SALT_COMMITMENT, twoWalletRoot, _keys(6));
        registry.registerDID(DID, SALT_COMMITMENT, twoWalletRoot, _keys(5));

        vm.expectRevert("DID: keys 1..5");
        registry.updateGovernanceKeys(DID, _keys(6));
        vm.stopPrank();

        DIDRegistryV2.DIDEntry memory entry = registry.getDID(DID);
        assertEq(entry.governanceKeys.length, registry.MAX_GOVERNANCE_KEYS());
        for (uint256 i = 0; i < entry.governanceKeys.length; i++) {
            assertTrue(entry.governanceKeys[i] != WALLET_A);
            assertTrue(entry.governanceKeys[i] != WALLET_B);
        }
        assertEq(entry.spendingKeyRoot, twoWalletRoot);
    }

    function test_RegisterRejectsZeroAndDuplicateGovernanceKeys() public {
        bytes32 spendingRoot = spendingTree.assign(WALLET_A, SLOT_A);
        address[] memory zeroKey = new address[](2);
        zeroKey[0] = CONTROLLER;
        zeroKey[1] = address(0);
        address[] memory duplicateKey = new address[](2);
        duplicateKey[0] = CONTROLLER;
        duplicateKey[1] = CONTROLLER;

        vm.startPrank(CONTROLLER);
        vm.expectRevert("DID: zero key");
        registry.registerDID(DID, SALT_COMMITMENT, spendingRoot, zeroKey);
        vm.expectRevert("DID: duplicate key");
        registry.registerDID(DID, SALT_COMMITMENT, spendingRoot, duplicateKey);
        vm.stopPrank();

        assertFalse(registry.isRegistered(DID));
        assertEq(registry.didCount(), 0);
    }

    function test_InvalidGovernanceRotationsAreAtomic() public {
        bytes32 spendingRoot = spendingTree.assign(WALLET_A, SLOT_A);
        _register(spendingRoot, _keys(1));
        address[] memory zeroKey = new address[](2);
        zeroKey[0] = CONTROLLER;
        zeroKey[1] = address(0);
        address[] memory duplicateKey = new address[](2);
        duplicateKey[0] = CONTROLLER;
        duplicateKey[1] = CONTROLLER;

        vm.startPrank(CONTROLLER);
        vm.expectRevert("DID: zero key");
        registry.updateGovernanceKeys(DID, zeroKey);
        vm.expectRevert("DID: duplicate key");
        registry.updateGovernanceKeys(DID, duplicateKey);
        vm.stopPrank();

        DIDRegistryV2.DIDEntry memory entry = registry.getDID(DID);
        assertEq(entry.governanceKeys.length, 1);
        assertEq(entry.governanceKeys[0], CONTROLLER);
    }

    function test_ValidRotationRetainsStableControllerAuthority() public {
        bytes32 initialRoot = spendingTree.assign(WALLET_A, SLOT_A);
        _register(initialRoot, _keys(1));
        address[] memory rotatedKeys = _keys(2);

        vm.prank(CONTROLLER);
        registry.updateGovernanceKeys(DID, rotatedKeys);
        bytes32 nextRoot = spendingTree.assign(WALLET_B, SLOT_B);
        vm.prank(CONTROLLER);
        registry.updateSpendingKeyRoot(DID, nextRoot);

        DIDRegistryV2.DIDEntry memory entry = registry.getDID(DID);
        assertEq(entry.governanceKeys.length, 2);
        assertEq(entry.governanceKeys[0], CONTROLLER);
        assertEq(entry.governanceKeys[1], address(0xC012));
        assertEq(entry.spendingKeyRoot, nextRoot);
    }

    /// @dev Registration is commit-then-reveal now, and the commitment binds the registrant, so both
    ///      halves come from CONTROLLER. The roll is required: the reveal must be in a STRICTLY later
    ///      block than its commitment, which is what denies a front-runner the block of warning they
    ///      used to get from the mempool.
    function _register(bytes32 spendingRoot, address[] memory governanceKeys) private {
        _commitAs(CONTROLLER, spendingRoot, governanceKeys);
        vm.prank(CONTROLLER);
        registry.registerDID(DID, SALT_COMMITMENT, spendingRoot, governanceKeys);
    }

    function _commitAs(address registrant, bytes32 spendingRoot, address[] memory governanceKeys)
        private
    {
        bytes32 c = registry.registrationCommitment(
            DID, SALT_COMMITMENT, spendingRoot, governanceKeys, registrant
        );
        vm.prank(registrant);
        registry.commitRegistration(c);
        vm.roll(block.number + 1);
    }

    function _keys(uint256 count) private pure returns (address[] memory keys) {
        keys = new address[](count);
        keys[0] = CONTROLLER;
        for (uint256 i = 1; i < count; i++) {
            keys[i] = address(uint160(0xC011 + i));
        }
    }

    function _deployPoseidon() private returns (address deployed) {
        string[] memory lines = vm.split(vm.readFile("bytecode/Poseidon2.bytecode"), "\n");
        uint256 i = lines.length;
        while (i > 0 && bytes(lines[i - 1]).length == 0) i--;
        bytes memory code = vm.parseBytes(lines[i - 1]);
        assembly {
            deployed := create(0, add(code, 0x20), mload(code))
        }
        require(deployed != address(0), "poseidon deploy failed");
    }

    // ---------- the front-running vector (Oct 2026 review, §5.1) ----------

    /**
     * THE ATTACK, as it worked before commit–reveal. A pending `registerDID` revealed the DID and its
     * salt commitment in the clear, and `callerIsKey` only checked the caller appeared in the
     * governance-key array THEY supplied. So a mempool watcher took the victim's `did`, substituted
     * their own address as the governance key, and landed first: the victim reverted with
     * `DID: exists`, and the attacker held governance over that DID, `updateSpendingKeyRoot`
     * included. The victim could not even fall back to a second DID, because an Identity Keeper
     * refuses a subject that derives a different one than it is already bound to.
     *
     * Note this is NOT squatting by guessing. The DID is a keyed PRF of the subject id and cannot be
     * predicted. Front-running needs no prediction, only a block of warning.
     */
    function test_AFrontRunnerCannotStealARevealedDid() public {
        address attacker = address(0xBAD);
        address[] memory attackerKeys = new address[](1);
        attackerKeys[0] = attacker;

        // The victim commits. Nothing about the DID is on chain yet except this digest.
        _commitAs(CONTROLLER, bytes32(0), _keys(1));

        // The attacker has now seen the victim's reveal in the mempool and tries to land first with
        // the same DID under their OWN key. They have no commitment for that shape, and cannot get
        // one into an earlier block than this one.
        vm.prank(attacker);
        vm.expectRevert("DID: no earlier commitment");
        registry.registerDID(DID, SALT_COMMITMENT, bytes32(0), attackerKeys);

        // And the victim's own registration still lands.
        vm.prank(CONTROLLER);
        registry.registerDID(DID, SALT_COMMITMENT, bytes32(0), _keys(1));
        assertEq(registry.getDID(DID).governanceKeys[0], CONTROLLER, "the victim holds their own DID");
    }

    /**
     * A commitment is bound to its registrant. The case where that matters is subtle: replaying
     * someone's commitment VERBATIM is already refused by `callerIsKey`, since the attacker is not in
     * the committed key set. The binding earns its keep when the attacker IS a listed key: a
     * co-signer, say, and tries to drive the registration themselves.
     */
    function test_AListedKeyCannotDriveAnotherPartysCommitment() public {
        address coSigner = address(0xBAD);
        address[] memory shared = new address[](2);
        shared[0] = CONTROLLER;
        shared[1] = coSigner;

        _commitAs(CONTROLLER, bytes32(0), shared);     // CONTROLLER committed, nobody else

        vm.prank(coSigner);                            // `callerIsKey` is satisfied here
        vm.expectRevert("DID: no earlier commitment"); // the registrant binding is what refuses
        registry.registerDID(DID, SALT_COMMITMENT, bytes32(0), shared);

        vm.prank(CONTROLLER);                          // and the committer still proceeds
        registry.registerDID(DID, SALT_COMMITMENT, bytes32(0), shared);
        assertTrue(registry.getDID(DID).exists);
    }

    /// Same block is not enough: a reveal must trail its commitment, or the mempool window reopens.
    function test_ARevealInTheCommitmentsOwnBlockIsRefused() public {
        bytes32 c = registry.registrationCommitment(
            DID, SALT_COMMITMENT, bytes32(0), _keys(1), CONTROLLER
        );
        vm.startPrank(CONTROLLER);
        registry.commitRegistration(c);          // no vm.roll
        vm.expectRevert("DID: no earlier commitment");
        registry.registerDID(DID, SALT_COMMITMENT, bytes32(0), _keys(1));
        vm.stopPrank();
    }

    // ---------- slot allocation (the collision that used to be unrecoverable) ----------

    /**
     * TWO DIDS THAT SHARE THEIR LOW 16 BITS MUST BOTH REGISTER. Slots used to be the low `depth` bits
     * of the DID, so 254-bit keys folded into 2^16 slots and collided on the birthday bound: a 1%
     * chance by the 37th DID, 50% by the 302nd. A collision was a hard revert rather than a probe,
     * and an Identity Keeper derives a DID deterministically from the subject, so the unlucky party
     * had no second DID to fall back to. Not a capacity limit; a lockout.
     */
    function test_TwoDidsSharingTheirLow16BitsBothRegister() public {
        bytes32 didA = DID;
        bytes32 didB = bytes32(uint256(DID) ^ (uint256(1) << 100));   // same low 16, different DID
        assertEq(uint256(didA) & 0xffff, uint256(didB) & 0xffff, "the test is only meaningful if they collide");
        assertTrue(didA != didB);

        _register(bytes32(0), _keys(1));

        address other = address(0xC0FFEE);
        address[] memory keysB = new address[](1);
        keysB[0] = other;
        bytes32 cB = registry.registrationCommitment(didB, SALT_COMMITMENT, bytes32(0), keysB, other);
        vm.prank(other);
        registry.commitRegistration(cB);
        vm.roll(block.number + 1);
        vm.prank(other);
        registry.registerDID(didB, SALT_COMMITMENT, bytes32(0), keysB);

        assertTrue(registry.getDID(didA).exists, "first DID holds");
        assertTrue(registry.getDID(didB).exists, "and the colliding one registers too");

        // Distinct slots, and each keeps the one it was given.
        (, uint256 idxA) = registry.getMerkleProof(didA);
        (, uint256 idxB) = registry.getMerkleProof(didB);
        assertTrue(idxA != idxB, "allocation-ordered slots never contend");
        assertEq(idxA, 0, "first in takes slot 0");
        assertEq(idxB, 1, "second takes slot 1");
    }

    /// A slot belongs to its DID for life: an update must not move it, or every witness goes stale.
    function test_ASlotIsStableAcrossSpendingKeyUpdates() public {
        _register(bytes32(0), _keys(1));
        (, uint256 before) = registry.getMerkleProof(DID);
        vm.prank(CONTROLLER);
        registry.updateSpendingKeyRoot(DID, keccak256("a different wallet set"));
        (, uint256 afterUpdate) = registry.getMerkleProof(DID);
        assertEq(before, afterUpdate, "the slot is the DID's for life");
    }
}
