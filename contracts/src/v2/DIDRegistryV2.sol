// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./libraries/PoseidonSparseTree.sol";
import "./libraries/GapLib.sol";
import "../interfaces/IPoseidon2.sol";

/**
 * @title DIDRegistryV2
 * @notice Singleton DID registry per handoff/03 §2: DID → {privateSaltCommitment (immutable),
 *         spendingKeyRoot (mutable), governanceKeys (mutable)}; sparse Poseidon tree → DID Root.
 * @dev Leaf = H2(H2(did, privateSaltCommitment), spendingKeyRoot), placed at an ALLOCATION-ORDERED index (first DID in takes slot 0, and keeps it).
 *      The root is ON-CHAIN and canonical (reviewer point): the Session Manager pins the proof's
 *      didRoot public input to root(); the offchain indexer supplies sibling paths only.
 */
contract DIDRegistryV2 {
    using PoseidonSparseTree for PoseidonSparseTree.Tree;

    uint256 public constant MAX_GOVERNANCE_KEYS = 5;

    struct DIDEntry {
        bytes32 privateSaltCommitment; // H2(privateSalt, 0), IMMUTABLE
        bytes32 spendingKeyRoot;       // Merkle root over fund-holding addresses, mutable
        address[] governanceKeys;      // Governance Keys: control the mutable fields
        uint256 registeredAt;
        bool exists;
    }

    address public immutable poseidon;
    uint256 public immutable registrationFee;
    address public immutable feeRecipient;

    PoseidonSparseTree.Tree private _tree;
    mapping(bytes32 => DIDEntry) private _dids;
    uint256 public didCount;

    event DIDRegistered(bytes32 indexed did, bytes32 privateSaltCommitment, bytes32 spendingKeyRoot);
    event SpendingKeyRootUpdated(bytes32 indexed did, bytes32 newSpendingKeyRoot);
    event GovernanceKeysUpdated(bytes32 indexed did);
    event DIDRootUpdated(bytes32 newRoot, uint256 didCount);

    constructor(address _poseidon, uint256 _depth, uint256 _fee, address _feeRecipient) {
        require(_poseidon != address(0), "DID: poseidon");
        poseidon = _poseidon;
        registrationFee = _fee;
        feeRecipient = _fee > 0 ? _feeRecipient : address(0);
        _tree.init(_poseidon, _depth);
    }

    modifier onlyGovernance(bytes32 did) {
        require(_isGovernanceKey(did, msg.sender), "DID: not governance key");
        _;
    }

    /// Commitment => the block it was made in. Consumed by `registerDID`.
    mapping(bytes32 => uint256) private _registrationCommitment;

    event RegistrationCommitted(bytes32 indexed commitment, address indexed registrant);

    /**
     * @notice The digest a registrant commits to before revealing a DID.
     * @dev    `registrant` is bound in, so one party's commitment is useless to another.
     */
    function registrationCommitment(
        bytes32 did,
        bytes32 privateSaltCommitment,
        bytes32 spendingKeyRoot,
        address[] memory governanceKeys,
        address registrant
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(
            "gap/did-registration/v1", did, privateSaltCommitment, spendingKeyRoot,
            governanceKeys, registrant
        ));
    }

    /**
     * @notice Step one of registration: commit, then reveal in a later block.
     * @dev    WHAT THIS STOPS. A pending `registerDID` used to reveal the DID and its salt
     *         commitment in the clear, while `callerIsKey` only checked that the caller appeared in
     *         the `governanceKeys` array THEY THEMSELVES supplied. So anyone watching the mempool
     *         could take the victim's `did`, substitute their own address as the governance key, and
     *         land first. The victim's transaction then reverted with `DID: exists`, the ATTACKER
     *         held governance over that DID, including `updateSpendingKeyRoot`, and the victim
     *         could not fall back to another, because an Identity Keeper refuses a subject that
     *         derives a different DID than the one it is already bound to.
     *
     *         An October 2026 review raised this as DID squatting. Squatting by GUESSING is not
     *         feasible: the DID is a keyed PRF of the subject id, so it cannot be predicted, but
     *         front-running needs no prediction, only a block of warning.
     *
     *         Commit–reveal removes the warning. The DID is secret until the reveal, and by then an
     *         attacker would need a commitment from an EARLIER block bound to their own address.
     *         This was chosen over an issuer signature because it closes the vector inside this one
     *         contract: no reference to the IK registry, no constructor change, and DIDs stay
     *         issued off-chain by the Identity Keeper, which is what the handoff spec specifies.
     */
    function commitRegistration(bytes32 commitment) external {
        require(commitment != bytes32(0), "DID: zero commitment");
        require(_registrationCommitment[commitment] == 0, "DID: already committed");
        _registrationCommitment[commitment] = block.number;
        emit RegistrationCommitted(commitment, msg.sender);
    }

    function registerDID(
        bytes32 did,
        bytes32 privateSaltCommitment,
        bytes32 spendingKeyRoot,
        address[] calldata governanceKeys
    ) external payable {
        require(GapLib.isField(did), "DID: not field element");
        require(!_dids[did].exists, "DID: exists");
        require(privateSaltCommitment != bytes32(0), "DID: salt commitment");
        _validateGovernanceKeys(governanceKeys);
        require(msg.value >= registrationFee, "DID: fee");
        bool callerIsKey = false;
        for (uint256 i = 0; i < governanceKeys.length; i++) {
            if (governanceKeys[i] == msg.sender) callerIsKey = true;
        }
        require(callerIsKey, "DID: caller not in keys");

        // LAST, and deliberately so. A malformed registration should say what is malformed about it
        // rather than complain about a commitment it was never going to get to use, so the gate
        // guards a registration that is otherwise ready, and is consumed just before the writes.
        // A STRICTLY EARLIER block, so a reveal cannot share a block with its own commitment.
        bytes32 commitment = registrationCommitment(
            did, privateSaltCommitment, spendingKeyRoot, governanceKeys, msg.sender
        );
        uint256 committedAt = _registrationCommitment[commitment];
        require(committedAt != 0 && committedAt < block.number, "DID: no earlier commitment");
        delete _registrationCommitment[commitment];

        // Allocation-ordered: a fresh slot per DID, so two unrelated DIDs can never contend for
        // one. Uniqueness is `_dids[did].exists` above and never was the tree's job.
        uint256 index = _tree.allocate(did);

        DIDEntry storage e = _dids[did];
        e.privateSaltCommitment = privateSaltCommitment;
        e.spendingKeyRoot = spendingKeyRoot;
        e.governanceKeys = governanceKeys;
        e.registeredAt = block.timestamp;
        e.exists = true;
        didCount++;

        _tree.set(index, _leaf(did, privateSaltCommitment, spendingKeyRoot));
        if (registrationFee > 0 && feeRecipient != address(0)) {
            (bool ok,) = feeRecipient.call{value: msg.value}("");
            require(ok, "DID: fee transfer");
        }

        emit DIDRegistered(did, privateSaltCommitment, spendingKeyRoot);
        emit DIDRootUpdated(_tree.root, didCount);
    }

    function updateSpendingKeyRoot(bytes32 did, bytes32 newSpendingKeyRoot) external onlyGovernance(did) {
        DIDEntry storage e = _dids[did];
        require(e.exists, "DID: not found");
        e.spendingKeyRoot = newSpendingKeyRoot;
        (uint256 slot, bool placed) = _tree.slotOf(did);
        require(placed, "DID: not in tree");
        _tree.set(slot, _leaf(did, e.privateSaltCommitment, newSpendingKeyRoot));
        emit SpendingKeyRootUpdated(did, newSpendingKeyRoot);
        emit DIDRootUpdated(_tree.root, didCount);
    }

    function updateGovernanceKeys(bytes32 did, address[] calldata newKeys) external onlyGovernance(did) {
        _validateGovernanceKeys(newKeys);
        _dids[did].governanceKeys = newKeys;
        emit GovernanceKeysUpdated(did);
    }

    // ---------- views ----------

    /// @notice Canonical on-chain DID Root (ZK public witness).
    function root() external view returns (bytes32) {
        return _tree.root;
    }

    function getDID(bytes32 did) external view returns (DIDEntry memory) {
        return _dids[did];
    }

    function isRegistered(bytes32 did) external view returns (bool) {
        return _dids[did].exists;
    }

    /// @notice Sibling path for the circuit witness (local/demo convenience; indexer in prod).
    function getMerkleProof(bytes32 did) external view returns (bytes32[] memory siblings, uint256 index) {
        bool placed;
        (index, placed) = _tree.slotOf(did);
        require(placed, "DID: not in tree");
        siblings = _tree.proof(index);
    }

    function treeDepth() external view returns (uint256) {
        return _tree.depth;
    }

    function _leaf(bytes32 did, bytes32 saltCommitment, bytes32 spendingKeyRoot) private view returns (bytes32) {
        IPoseidon2 h = IPoseidon2(poseidon);
        return h.poseidon([h.poseidon([did, saltCommitment]), spendingKeyRoot]);
    }

    function _isGovernanceKey(bytes32 did, address key) private view returns (bool) {
        address[] storage keys = _dids[did].governanceKeys;
        for (uint256 i = 0; i < keys.length; i++) {
            if (keys[i] == key) return true;
        }
        return false;
    }

    function _validateGovernanceKeys(address[] calldata keys) private pure {
        require(keys.length >= 1 && keys.length <= MAX_GOVERNANCE_KEYS, "DID: keys 1..5");
        for (uint256 i = 0; i < keys.length; i++) {
            require(keys[i] != address(0), "DID: zero key");
            for (uint256 j = i + 1; j < keys.length; j++) {
                require(keys[i] != keys[j], "DID: duplicate key");
            }
        }
    }
}
