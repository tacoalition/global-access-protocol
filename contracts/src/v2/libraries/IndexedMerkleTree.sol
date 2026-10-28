// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./PoseidonSparseTree.sol";
import "../../interfaces/IPoseidon2.sol";

/**
 * @title IndexedMerkleTree
 * @notice Sorted-linked-list Merkle tree (Aztec-style "indexed Merkle tree") for full-key
 *         NON-membership proofs (GAP-H1). Each live node is a list element {key, nextKey};
 *         its leaf is H2(key, nextKey) stored at the node's ALLOCATION slot (not key-derived,
 *         so keys never collide at any depth, tree depth caps only the number of CONCURRENT
 *         live keys). Genesis sentinel {0, 0} lives at slot 0 and is undeletable.
 * @dev Non-membership of `k`: the circuit proves MEMBERSHIP of a "low leaf" (lowKey, nextKey)
 *      with lowKey < k AND (nextKey == 0 OR k < nextKey). Soundness rests on the sorted-list
 *      invariant this library enforces on every insert/remove: keys strictly ascend, are unique
 *      and non-zero, the tail's nextKey is 0, and dead slots hold leaf 0 (never a stale node: 
 *      a reusable dead {0,0} node would forge a genesis-shaped low leaf).
 *      Writers pass a predecessor-slot hint validated in O(1); `findPredecessor` (O(n) walk)
 *      serves local/demo callers, production TMs use an indexer for hints.
 */
library IndexedMerkleTree {
    using PoseidonSparseTree for PoseidonSparseTree.Tree;

    struct Node {
        bytes32 key;
        bytes32 nextKey;
        bool exists;
    }

    struct List {
        PoseidonSparseTree.Tree tree;
        Node[] nodes;                        // slot-indexed; nodes[0] = genesis {0,0}
        mapping(bytes32 => uint256) nodeIndex; // key → slot; 0 means absent (genesis key 0 IS slot 0)
        uint256[] freeSlots;                 // reclaimed slots (their leaves are zeroed)
    }

    function init(List storage l, address poseidon_, uint256 depth_) internal {
        l.tree.init(poseidon_, depth_);
        l.nodes.push(Node(bytes32(0), bytes32(0), true));
        l.tree.set(0, _leaf(l, bytes32(0), bytes32(0)));
    }

    /// @notice Insert `key` after the live predecessor at slot `predIdx`. Hint is fully
    ///         validated: a wrong or dead predecessor reverts, it can never corrupt the list.
    function insert(List storage l, bytes32 key, uint256 predIdx) internal {
        require(key != bytes32(0), "IMT: zero key");
        require(l.nodeIndex[key] == 0, "IMT: key present");
        Node storage pred = l.nodes[predIdx];
        require(pred.exists, "IMT: dead predecessor");
        require(uint256(pred.key) < uint256(key), "IMT: bad predecessor");
        require(pred.nextKey == bytes32(0) || uint256(key) < uint256(pred.nextKey), "IMT: bad predecessor");

        bytes32 next = pred.nextKey;
        uint256 slot;
        if (l.freeSlots.length > 0) {
            slot = l.freeSlots[l.freeSlots.length - 1];
            l.freeSlots.pop();
            l.nodes[slot] = Node(key, next, true);
        } else {
            require(l.nodes.length < (1 << l.tree.depth), "IMT: full");
            slot = l.nodes.length;
            l.nodes.push(Node(key, next, true));
        }
        l.nodeIndex[key] = slot;
        pred.nextKey = key;
        l.tree.set(predIdx, _leaf(l, pred.key, key));
        l.tree.set(slot, _leaf(l, key, next));
    }

    /// @notice Remove `key`; `predIdx` must be its live predecessor (pred.nextKey == key).
    ///         Genesis (slot 0, key 0) is undeletable: nodeIndex[0] == 0 reads as absent.
    function remove(List storage l, bytes32 key, uint256 predIdx) internal {
        uint256 slot = l.nodeIndex[key];
        require(slot != 0, "IMT: key absent");
        Node storage pred = l.nodes[predIdx];
        require(pred.exists && pred.nextKey == key, "IMT: bad predecessor");

        bytes32 next = l.nodes[slot].nextKey;
        pred.nextKey = next;
        delete l.nodes[slot];      // key=0, nextKey=0, exists=false, dead slots are inert
        delete l.nodeIndex[key];
        l.freeSlots.push(slot);
        l.tree.set(predIdx, _leaf(l, pred.key, next));
        l.tree.set(slot, bytes32(0));
    }

    function contains(List storage l, bytes32 key) internal view returns (bool) {
        return l.nodeIndex[key] != 0;
    }

    /// @notice O(n) sorted walk from genesis to the node preceding `key` (works whether or not
    ///         `key` is present). Local/demo convenience, production writers pass indexer hints.
    function findPredecessor(List storage l, bytes32 key) internal view returns (uint256 idx) {
        Node storage n = l.nodes[0];
        while (n.nextKey != bytes32(0) && uint256(n.nextKey) < uint256(key)) {
            idx = l.nodeIndex[n.nextKey];
            n = l.nodes[idx];
        }
    }

    /// @notice The non-membership witness for `key`: its low leaf + sibling path.
    function lowLeaf(List storage l, bytes32 key)
        internal view returns (uint256 index, bytes32 lowKey, bytes32 nextKey, bytes32[] memory siblings)
    {
        index = findPredecessor(l, key);
        Node storage n = l.nodes[index];
        return (index, n.key, n.nextKey, l.tree.proof(index));
    }

    function root(List storage l) internal view returns (bytes32) {
        return l.tree.root;
    }

    function _leaf(List storage l, bytes32 key, bytes32 nextKey) private view returns (bytes32) {
        return IPoseidon2(l.tree.poseidon).poseidon([key, nextKey]);
    }
}
