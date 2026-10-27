// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "../../interfaces/IPoseidon2.sol";

/**
 * @title PoseidonSparseTree
 * @notice Storage-based sparse Merkle tree over Poseidon(2), fixed depth.
 * @dev Leaf index is ALLOCATION-ORDERED: the first key to arrive takes slot 0, the next slot 1, and a
 *      key keeps its slot for life. Empty leaf = 0; zeros[i+1] = H(zeros[i], zeros[i]).
 *
 *      WHAT THIS REPLACES, AND WHY. The index used to be the low `depth` bits of the key. With
 *      254-bit keys folded into 2^16 slots that is the birthday problem: a 1% chance of a collision
 *      by the 37th key and 50% by the 302nd, and a collision was a HARD REVERT, not a probe, so the
 *      unlucky party simply could not register. Worse, an Identity Keeper derives a DID
 *      deterministically from the subject, so there was no second DID to fall back to.
 *
 *      The sibling `IndexedMerkleTree` had this right all along ("keys never collide at any depth, 
 *      slots are allocation-ordered"); it was never carried across.
 *
 *      THIS COSTS NO CIRCUIT CHANGE AND NO CEREMONY, which is what makes it the right fix rather than
 *      a deeper tree. `MerkleMembership` already takes `pathIndices` as a WITNESS, and the leaf binds
 *      the key, H2(H2(did, saltCommit), spendingKeyRoot), so position never carried identity. The
 *      proof says "this leaf is in the tree at the position I claim", which is true at any slot.
 *      Uniqueness was never the tree's job either: the registry's own `exists` mapping enforces it.
 *      Every set() costs `depth` Poseidon calls, O(depth) updates, matches the circuit's
 *      MerkleTreeVerifier exactly (left/right by index bit, Poseidon(2) per level).
 */
library PoseidonSparseTree {
    struct Tree {
        uint256 depth;
        address poseidon;
        bytes32 root;
        // nodes[level][index]: level 0 = leaves. Only non-zero-path nodes are stored.
        mapping(uint256 => mapping(uint256 => bytes32)) nodes;
        // zeros[level]: precomputed empty-subtree hash per level.
        mapping(uint256 => bytes32) zeros;
        // Allocation state. `slotPlusOne` is offset by one so that 0 means "never allocated" and
        // slot 0 remains a usable slot.
        uint256 nextIndex;
        mapping(bytes32 => uint256) slotPlusOne;
        bool initialized;
    }

    function init(Tree storage t, address poseidon_, uint256 depth_) internal {
        require(!t.initialized, "SMT: initialized");
        require(depth_ > 0 && depth_ <= 32, "SMT: bad depth");
        t.depth = depth_;
        t.poseidon = poseidon_;
        bytes32 z = bytes32(0);
        t.zeros[0] = z;
        for (uint256 i = 1; i <= depth_; i++) {
            z = IPoseidon2(poseidon_).poseidon([z, z]);
            t.zeros[i] = z;
        }
        t.root = z;
        t.initialized = true;
    }

    /**
     * @notice The slot this key already holds, allocating the next free one if it holds none.
     * @dev    Reverts only when the tree is genuinely full, 2^depth distinct keys, rather than on
     *         the first unlucky pair.
     */
    function allocate(Tree storage t, bytes32 key) internal returns (uint256) {
        uint256 existing = t.slotPlusOne[key];
        if (existing != 0) return existing - 1;
        require(t.nextIndex < (1 << t.depth), "SMT: tree full");
        uint256 index = t.nextIndex;
        t.nextIndex = index + 1;
        t.slotPlusOne[key] = index + 1;
        return index;
    }

    /// @notice The slot this key holds, and whether it holds one. Never allocates.
    function slotOf(Tree storage t, bytes32 key) internal view returns (uint256 index, bool exists) {
        uint256 plusOne = t.slotPlusOne[key];
        return plusOne == 0 ? (0, false) : (plusOne - 1, true);
    }

    /// @notice How many slots have been handed out. `2 ** depth` is the ceiling.
    function allocated(Tree storage t) internal view returns (uint256) {
        return t.nextIndex;
    }

    /// @notice Current leaf value at index (0 if never set).
    function leafAt(Tree storage t, uint256 index) internal view returns (bytes32) {
        return t.nodes[0][index];
    }

    /// @notice Set leaf at `index` to `value` and bubble the root up.
    function set(Tree storage t, uint256 index, bytes32 value) internal {
        require(t.initialized, "SMT: not initialized");
        require(index < (1 << t.depth), "SMT: index out of range");
        IPoseidon2 hasher = IPoseidon2(t.poseidon);

        t.nodes[0][index] = value;
        bytes32 node = value;
        uint256 idx = index;
        for (uint256 level = 0; level < t.depth; level++) {
            uint256 siblingIdx = idx ^ 1;
            bytes32 sibling = t.nodes[level][siblingIdx];
            if (sibling == bytes32(0)) sibling = _zeroOrStored(t, level, siblingIdx);
            if (idx & 1 == 0) {
                node = hasher.poseidon([node, sibling]);
            } else {
                node = hasher.poseidon([sibling, node]);
            }
            idx >>= 1;
            t.nodes[level + 1][idx] = node;
        }
        t.root = node;
    }

    /// @dev A stored zero is indistinguishable from empty; both hash as the level's zero.
    function _zeroOrStored(Tree storage t, uint256 level, uint256 idx) private view returns (bytes32) {
        bytes32 stored = t.nodes[level][idx];
        return stored == bytes32(0) ? t.zeros[level] : stored;
    }

    /// @notice Sibling path for `index` (level 0..depth-1), lets tests/CLI build witnesses on-chain-free.
    function proof(Tree storage t, uint256 index) internal view returns (bytes32[] memory siblings) {
        siblings = new bytes32[](t.depth);
        uint256 idx = index;
        for (uint256 level = 0; level < t.depth; level++) {
            uint256 siblingIdx = idx ^ 1;
            siblings[level] = _zeroOrStored(t, level, siblingIdx);
            idx >>= 1;
        }
    }
}
