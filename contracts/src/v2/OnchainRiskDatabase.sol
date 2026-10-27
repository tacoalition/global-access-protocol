// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./libraries/IndexedMerkleTree.sol";
import "../interfaces/IPoseidon2.sol";
import "./libraries/GapLib.sol";

/**
 * @title OnchainRiskDatabase (ORDB)
 * @notice Per-TM, per-contract risk database per handoff/03 §11: KV hashedPseudonym → RiskFlag
 *         bitmask + an INDEXED Merkle tree (sorted linked list) → Risk Root, the ZK full-key
 *         NON-membership witness (GAP-H1). ORDB ID = address.
 * @dev Also stores the TM's ECIES monitor key ON-CHAIN (adversarial finding #11) so the Session
 *      Manager can pin the encrypted-pseudonym public inputs, and supports flagging a CONTRACT
 *      address (Stop-Transfer groundwork). The tree encodes only key PRESENCE: a clean user
 *      proves a low leaf (lowKey, nextKey) brackets their pseudonym; flag bits live in `_flags`.
 *      Keys never collide at any depth (slots are allocation-ordered), so flag/unflag of
 *      low-bit-sharing pseudonyms are fully independent.
 */
contract OnchainRiskDatabase {
    using IndexedMerkleTree for IndexedMerkleTree.List;

    // Standard Risk-Flag codes (per Classification Regime; degrees in reserved sub-fields)
    uint256 public constant FLAG_SANDWICH_ATTACKER      = 1 << 0;
    uint256 public constant FLAG_WASH_TRADER            = 1 << 1;
    uint256 public constant FLAG_FRONT_RUNNER           = 1 << 2;
    uint256 public constant FLAG_SANCTIONS_LINKED       = 1 << 3;
    uint256 public constant FLAG_HIGH_RISK_JURISDICTION = 1 << 4;
    uint256 public constant FLAG_SYBIL_ATTACKER         = 1 << 5;
    uint256 public constant FLAG_STOP_TRANSFER          = 1 << 6;

    struct FlagRecord {
        uint256 flags;
        uint256 flaggedAt;
        uint256 lastUpdated;
    }

    struct MonitorKey {
        uint256 pubKeyX;   // Baby-Jubjub point (matches the in-circuit ECIES, handoff/04 §2)
        uint256 pubKeyY;
        bytes32 keyId;
        uint256 activatedAt;
    }

    address public owner;
    address public transactionMonitor;   // sole flag writer
    address public governance;           // unflag authority (appeals; optional multi-sig)
    address public monitoredContract;    // the single contract this TM watches (Local Monitoring)
    address public immutable poseidon;

    IndexedMerkleTree.List private _list;
    mapping(bytes32 => FlagRecord) private _flags;
    MonitorKey public currentMonitorKey;
    MonitorKey public previousMonitorKey; // grace-period decrypt fallback (handoff/04 §7)

    event PseudonymFlagged(bytes32 indexed pseudonymHash, uint256 flags, bytes32 riskRoot);
    event PseudonymUnflagged(bytes32 indexed pseudonymHash, uint256 flags, bytes32 riskRoot);
    event UnflagProposed(bytes32 indexed pseudonymHash, uint256 flagBits, address indexed monitor);
    event UnflagProposalWithdrawn(bytes32 indexed pseudonymHash, address indexed monitor);
    event MonitorKeyRotated(bytes32 indexed keyId);
    event RolesUpdated(address transactionMonitor, address governance);

    modifier onlyTM() { require(msg.sender == transactionMonitor, "ORDB: not TM"); _; }
    modifier onlyGovernance() { require(msg.sender == governance, "ORDB: not governance"); _; }
    modifier onlyOwner() { require(msg.sender == owner, "ORDB: not owner"); _; }

    constructor(
        address _owner,
        address _transactionMonitor,
        address _governance,
        address _monitoredContract,
        address _poseidon,
        uint256 _depth,
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        bytes32 _keyId
    ) {
        require(_owner != address(0) && _transactionMonitor != address(0), "ORDB: zero addr");
        owner = _owner;
        transactionMonitor = _transactionMonitor;
        governance = _governance == address(0) ? _owner : _governance;
        monitoredContract = _monitoredContract;
        poseidon = _poseidon;
        _list.init(_poseidon, _depth);
        currentMonitorKey = MonitorKey(_pubKeyX, _pubKeyY, _keyId, block.timestamp);
    }

    // ---------- flagging (TM) / unflagging (governance appeals) ----------
    // Hinted variants verify the predecessor slot in O(1) (production path, hints come from an
    // indexer); the unhinted variants walk the sorted list on-chain (O(live flags), local/demo).

    function flagPseudonym(bytes32 pseudonymHash, uint256 flagBits) external onlyTM {
        _flag(pseudonymHash, flagBits, _list.findPredecessor(pseudonymHash));
    }

    function flagPseudonym(bytes32 pseudonymHash, uint256 flagBits, uint256 predIndex) external onlyTM {
        _flag(pseudonymHash, flagBits, predIndex);
    }

    /// @notice Flag a smart-contract address (Stop-Transfer on assets held via contracts).
    /// @dev Same machinery as flagPseudonym; the key is the zero-padded contract address.
    function flagContract(address target, uint256 flagBits) external onlyTM {
        require(target != address(0), "ORDB: zero addr"); // key 0 is the genesis sentinel
        bytes32 key = bytes32(uint256(uint160(target)));
        _flag(key, flagBits, _list.findPredecessor(key));
    }

    /**
     * @notice The Transaction Monitor raises an appeal. It cannot grant one.
     * @dev    TM PROPOSES, GOVERNANCE DISPOSES. The DSI Regulatory Model (p.10, §4.1) describes the
     *         remedy for a false positive as "a user will be able to appeal to a Transaction Monitor
     *         off chain to have their flag removed", which reads as though the TM clears it. An
     *         October 2026 review was right that ours does not: `flagPseudonym` is `onlyTM` while
     *         `unflagPseudonym` is `onlyGovernance`, and the TM does not hold that role.
     *
     *         The split is kept, deliberately, because a role that can both raise and clear a flag
     *         can be leaned on to quietly undo one, and the flag set is the only public record of
     *         monitoring activity there is. What was missing is that the appeal had no on-chain
     *         expression at all, so it happened entirely in private.
     *
     *         Now it is a two-party act with a visible trail: the monitor that heard the appeal says
     *         so here, and governance clears it. Neither can do both.
     */
    function proposeUnflag(bytes32 pseudonymHash, uint256 flagBits) external onlyTM {
        require(flagBits != 0, "ORDB: zero flags");
        require(_flags[pseudonymHash].flags & flagBits != 0, "ORDB: not flagged");
        _unflagProposal[pseudonymHash] = flagBits;
        emit UnflagProposed(pseudonymHash, flagBits, msg.sender);
    }

    /// @notice Withdraw an appeal the monitor no longer supports, before governance acts on it.
    function withdrawUnflagProposal(bytes32 pseudonymHash) external onlyTM {
        delete _unflagProposal[pseudonymHash];
        emit UnflagProposalWithdrawn(pseudonymHash, msg.sender);
    }

    function unflagPseudonym(bytes32 pseudonymHash, uint256 flagBits) external onlyGovernance {
        _consumeProposal(pseudonymHash, flagBits);
        _unflag(pseudonymHash, flagBits, _list.findPredecessor(pseudonymHash));
    }

    function unflagPseudonym(bytes32 pseudonymHash, uint256 flagBits, uint256 predIndex) external onlyGovernance {
        _consumeProposal(pseudonymHash, flagBits);
        _unflag(pseudonymHash, flagBits, predIndex);
    }

    /**
     * @dev Governance may clear only what a monitor actually proposed, and only once.
     *
     *      THE OPERATIONAL CONSEQUENCE IS REAL and belongs in DEPLOYMENT_RISKS.md: a monitor whose
     *      key is lost can no longer raise appeals, and governance cannot clear a flag without one.
     *      That is the cost of refusing to let any single role both raise and clear. Rotate the
     *      monitor key (`rotateMonitorKey`) rather than leaving appeals unanswerable.
     */
    function _consumeProposal(bytes32 pseudonymHash, uint256 flagBits) private {
        uint256 proposed = _unflagProposal[pseudonymHash];
        require(proposed != 0, "ORDB: no appeal raised");
        require(flagBits & ~proposed == 0, "ORDB: appeal does not cover these flags");
        delete _unflagProposal[pseudonymHash];
    }

    /// Flags a monitor has asked governance to clear. Cleared when governance acts, or withdrawn.
    mapping(bytes32 => uint256) private _unflagProposal;

    /// @notice Flags a monitor has asked governance to clear for this pseudonym, 0 when none.
    function unflagProposalOf(bytes32 pseudonymHash) external view returns (uint256) {
        return _unflagProposal[pseudonymHash];
    }

    function _flag(bytes32 key, uint256 flagBits, uint256 predIndex) private {
        require(key != bytes32(0) && GapLib.isField(key), "ORDB: bad key");
        require(flagBits != 0, "ORDB: zero flags");
        FlagRecord storage r = _flags[key];
        if (r.flaggedAt == 0) r.flaggedAt = block.timestamp;
        bool wasClean = r.flags == 0;
        r.flags |= flagBits;
        r.lastUpdated = block.timestamp;
        if (wasClean) _list.insert(key, predIndex); // presence-only: further bits don't move the tree
        emit PseudonymFlagged(key, r.flags, _list.root());
    }

    function _unflag(bytes32 key, uint256 flagBits, uint256 predIndex) private {
        require(key != bytes32(0), "ORDB: bad key");
        FlagRecord storage r = _flags[key];
        require(r.flags & flagBits != 0, "ORDB: not flagged");
        r.flags &= ~flagBits;
        r.lastUpdated = block.timestamp;
        if (r.flags == 0) _list.remove(key, predIndex);
        emit PseudonymUnflagged(key, r.flags, _list.root());
    }

    // ---------- monitor key (adversarial finding: on-chain key so SM can pin ECIES inputs) ----------

    function rotateMonitorKey(uint256 newX, uint256 newY, bytes32 newKeyId) external onlyTM {
        previousMonitorKey = currentMonitorKey;
        currentMonitorKey = MonitorKey(newX, newY, newKeyId, block.timestamp);
        emit MonitorKeyRotated(newKeyId);
    }

    function getMonitorKey() external view returns (uint256 x, uint256 y, bytes32 keyId) {
        return (currentMonitorKey.pubKeyX, currentMonitorKey.pubKeyY, currentMonitorKey.keyId);
    }

    // ---------- views ----------

    function root() external view returns (bytes32) { return _list.root(); }

    function isFlagged(bytes32 pseudonymHash) external view returns (bool) {
        return _flags[pseudonymHash].flags != 0;
    }

    /**
     * @notice True when `pseudonym` is flagged AND opens `commitment` under `blindingR`.
     * @dev    THE BINDING IS THE WHOLE POINT. `isFlagged` alone cannot justify revoking a session:
     *         a Transaction Monitor could present ANY pseudonym it already knows to be flagged and
     *         use it as grounds against ANY account. Checking that the pseudonym reopens the
     *         commitment this session was granted under ties the evidence to the session it is
     *         being used against.
     *
     *         Poseidon lives here rather than in SessionManager, which has no hash of its own: 
     *         the ORDB already holds one for its indexed tree, so the check costs no new wiring
     *         and no constructor change anywhere.
     *
     *         Publishing the pseudonym to call this costs nothing: a flagged pseudonym is already
     *         public, by necessity, because a clean holder proves NON-membership by bracketing
     *         their own key in this list. See ON_CHAIN_DISCLOSURE.md.
     */
    function isFlaggedForCommitment(bytes32 pseudonym, bytes32 blindingR, bytes32 commitment)
        external view returns (bool)
    {
        if (_flags[pseudonym].flags == 0) return false;
        return IPoseidon2(poseidon).poseidon([pseudonym, blindingR]) == commitment;
    }

    function getFlags(bytes32 pseudonymHash) external view returns (uint256) {
        return _flags[pseudonymHash].flags;
    }

    function hasFlag(bytes32 pseudonymHash, uint256 flagBits) external view returns (bool) {
        return _flags[pseudonymHash].flags & flagBits == flagBits;
    }

    /// @notice NON-membership witness: the low leaf bracketing `pseudonymHash` + its sibling path,
    ///         with the root it is valid for (one call = one block = consistent witness/root).
    ///         Local/demo convenience; indexer in prod. Reverts for a flagged key: no witness exists.
    function getNonMembershipWitness(bytes32 pseudonymHash)
        external view
        returns (uint256 lowIndex, bytes32 lowKey, bytes32 nextKey, bytes32[] memory siblings, bytes32 root_)
    {
        require(pseudonymHash != bytes32(0) && GapLib.isField(pseudonymHash), "ORDB: bad key");
        require(_flags[pseudonymHash].flags == 0, "ORDB: pseudonym flagged");
        (lowIndex, lowKey, nextKey, siblings) = _list.lowLeaf(pseudonymHash);
        root_ = _list.root();
    }

    /// @notice Predecessor-slot hint for the hinted flag/unflag variants (O(n) view walk).
    function findPredecessor(bytes32 key) external view returns (uint256) {
        return _list.findPredecessor(key);
    }

    function treeDepth() external view returns (uint256) { return _list.tree.depth; }

    function updateRoles(address newTM, address newGovernance) external onlyOwner {
        if (newTM != address(0)) transactionMonitor = newTM;
        if (newGovernance != address(0)) governance = newGovernance;
        emit RolesUpdated(transactionMonitor, governance);
    }
}

/**
 * @title ORDBFactory
 * @notice Deploys one ORDB per (TM, monitored contract). ORDB ID = deployed address.
 */
contract ORDBFactory {
    address public immutable poseidon;
    uint256 public immutable defaultDepth;

    event ORDBDeployed(address indexed ordb, address indexed transactionMonitor, address indexed monitoredContract);

    constructor(address _poseidon, uint256 _defaultDepth) {
        poseidon = _poseidon;
        defaultDepth = _defaultDepth;
    }

    function deployORDB(
        address owner,
        address transactionMonitor,
        address governance,
        address monitoredContract,
        uint256 pubKeyX,
        uint256 pubKeyY,
        bytes32 keyId
    ) external returns (address ordb) {
        ordb = address(new OnchainRiskDatabase(
            owner, transactionMonitor, governance, monitoredContract,
            poseidon, defaultDepth, pubKeyX, pubKeyY, keyId
        ));
        emit ORDBDeployed(ordb, transactionMonitor, monitoredContract);
    }
}
