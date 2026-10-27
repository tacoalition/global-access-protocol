// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./RegimeRegistry.sol";
import "./IKRegistryBase.sol";
import "./libraries/GapLib.sol";
import "./libraries/PoseidonSparseTree.sol";

/**
 * @title IdentityAnchor (ITA Contract)
 * @notice Per-ITA anchor per handoff/03 §4–§5 (P0-7 option 1): manages its OWN Identity Keepers
 *         in-anchor (via IKRegistryBase), and holds per-Attribute-Regime credential trees whose
 *         roots are the ZK public witnesses.
 * @dev ITA ID = this contract's address (deployed directly, permissionless).
 *      Credential leaf = Poseidon-chain(tag, ita, regimeHash, did, attrsHash, salt, ikId, expiresAt),
 *      computed OFFCHAIN by the IK (contains private data) and re-derived IN-CIRCUIT;
 *      the contract enforces (regime, DID) uniqueness: the Sybil half, and tree placement
 *      at an ALLOCATION-ORDERED index: a DID keeps the slot it is first given, so two DIDs can
 *      never contend for one. Revocation zeroes the leaf (membership proof fails).
 *      GAP-H4: IK revocation ALSO invalidates the credentials that IK already issued: the anchor
 *      tracks per-IK issuance refs and bulk-zeroes those leaves in bounded batches.
 */
contract IdentityAnchor is IKRegistryBase {
    using PoseidonSparseTree for PoseidonSparseTree.Tree;

    struct Credential {
        bytes32 commitment;          // the leaf (offchain-computed, in-circuit re-derived)
        bytes32 issuerIKId;
        uint256 issuedAt;
        uint256 expiresAt;           // 0 = none; informational mirror: the LEAF copy is proof-enforced (GAP-H2)
        bool revoked;
        /**
         * Issuer-set, opaque to this contract and to the circuit: it is in NO proof and binds
         * nothing. The whitepaper gives every Attribute Credential a metadata field, and Appendix III
         * is what it is for: an Identity Trust Anchor may require its Keepers to post the hash of a
         * PII identifier here, so a second Keeper can detect that this person already holds a
         * credential under this anchor. That is the on-chain half of Sybil resistance.
         *
         * BE CAREFUL WHAT GOES HERE. It is PUBLIC and permanent. The whitepaper names the hazard
         * itself: the hash of a low-entropy identifier (a 10-digit SSN is ~10^11 candidates) is a
         * dictionary attack away from being the identifier, and a DID is not private. An anchor that
         * wants this field should salt or pepper the identifier under its own key, not post a bare
         * hash. GAP does not and cannot enforce that, hence the warning rather than a check.
         */
        bytes32 metadata;
    }

    struct IssuanceRef {
        bytes32 regimeHash;
        bytes32 did;
    }

    uint256 public constant REVOKE_PURGE_BATCH = 16; // leaves zeroed atomically inside revokeIK

    address public immutable poseidon;
    uint256 public immutable credTreeDepth;

    mapping(bytes32 => PoseidonSparseTree.Tree) private _regimeTrees;   // regimeHash → tree
    mapping(bytes32 => mapping(bytes32 => Credential)) private _credentials; // regime → did → cred
    mapping(bytes32 => IssuanceRef[]) private _issuedBy;                // ikId → everything it issued
    mapping(bytes32 => uint256) private _purgeCursor;                   // ikId → refs processed
    // Dedupe: one ref per (ikId, regime, did): a same-IK revoke/reissue loop must not stuff the
    // atomic purge batch with stale refs (internal review finding).
    mapping(bytes32 => mapping(bytes32 => mapping(bytes32 => bool))) private _refSeen;

    event CredentialIssued(bytes32 indexed regimeHash, bytes32 indexed did, bytes32 indexed issuerIKId, bytes32 commitment, uint256 expiresAt, bytes32 metadata);
    event CredentialRevoked(bytes32 indexed regimeHash, bytes32 indexed did, string reason);
    event AttributeRegimeRootUpdated(bytes32 indexed regimeHash, bytes32 newRoot);
    event IKPurgeProgress(bytes32 indexed ikId, uint256 cursor, uint256 total);

    /// The shared regime registry this anchor's adoptions are checked against. Not optional: an
    /// anchor with no registry could adopt anything, which is the state this replaced.
    address public immutable regimeRegistry;

    constructor(address _admin, address _poseidon, uint256 _credTreeDepth, address _regimeRegistry) {
        require(_regimeRegistry != address(0), "ITA: regime registry");
        regimeRegistry = _regimeRegistry;
        require(_admin != address(0) && _poseidon != address(0), "ITA: zero addr");
        admin = _admin;
        poseidon = _poseidon;
        credTreeDepth = _credTreeDepth;
    }

    // ---------- regime adoption ----------

    /**
     * @notice Adopt an Attribute Regime this anchor will issue under.
     * @dev    THE REGIME MUST EXIST IN THE SHARED REGISTRY. An October 2026 review observed that
     *         `RegimeRegistry` was advisory-only, its own header said so, and no other contract read
     *         it, while the white paper (§3.3, §4.2) describes it as the enforced semantic backbone
     *         that anchors consult. A registry nothing reads is worse than no registry, because it
     *         reads as enforced.
     *
     *         So an anchor can no longer invent a regime. The hash it adopts has to be one the
     *         registry has a definition for, which is what makes "attribute index 2 means
     *         citizenship" a shared fact rather than a per-anchor convention.
     */
    function adoptRegime(bytes32 regimeHash) external onlyAdmin {
        require(RegimeRegistry(regimeRegistry).regimeExists(regimeHash), "ITA: regime not registered");
        require(!supportedRegimes[regimeHash], "ITA: adopted");
        supportedRegimes[regimeHash] = true;
        _supportedRegimeList.push(regimeHash);
        _regimeTrees[regimeHash].init(poseidon, credTreeDepth);
        emit RegimeAdopted(regimeHash);
    }

    // ---------- IK revocation + credential purge (GAP-H4) ----------

    /// @notice Revoke an IK: blocks new issuance immediately AND begins invalidating everything
    ///         it already issued: the first `REVOKE_PURGE_BATCH` leaves are zeroed in THIS tx
    ///         (shrinks the reviewed mint window); the remainder is purged permissionlessly.
    function revokeIK(bytes32 ikId) external onlyAdmin {
        _revokeIK(ikId, REVOKE_PURGE_BATCH);
    }

    /// @notice Gas-controlled variant (internal review finding): `initialPurge = 0` commits the revocation
    ///         without any tree work (guaranteed cheap at any depth); the purge follows separately.
    function revokeIK(bytes32 ikId, uint256 initialPurge) external onlyAdmin {
        _revokeIK(ikId, initialPurge);
    }

    function _revokeIK(bytes32 ikId, uint256 initialPurge) private {
        require(_iks[ikId].exists, "ITA: ik not found");
        require(!_iks[ikId].revoked, "ITA: already revoked");
        _iks[ikId].revoked = true;
        emit IKRevoked(ikId);
        if (initialPurge > 0) _purge(ikId, initialPurge);
    }

    /// @notice Permissionless continuation of a revoked IK's credential purge (bounded batches: 
    ///         no unbounded loop). Anyone may drive it; only revoked IKs are purgeable.
    function purgeRevokedIKCredentials(bytes32 ikId, uint256 maxCount) external {
        require(_iks[ikId].exists && _iks[ikId].revoked, "ITA: ik not revoked");
        require(maxCount > 0, "ITA: zero batch");
        _purge(ikId, maxCount);
    }

    function _purge(bytes32 ikId, uint256 maxCount) private {
        IssuanceRef[] storage refs = _issuedBy[ikId];
        uint256 cursor = _purgeCursor[ikId];
        uint256 end = cursor + maxCount > refs.length ? refs.length : cursor + maxCount;
        for (; cursor < end; cursor++) {
            IssuanceRef storage ref = refs[cursor];
            Credential storage c = _credentials[ref.regimeHash][ref.did];
            // skip if already revoked individually, or re-issued by another IK after a revoke
            if (c.revoked || c.issuerIKId != ikId) continue;
            c.revoked = true;
            PoseidonSparseTree.Tree storage tree = _regimeTrees[ref.regimeHash];
            (uint256 purgeSlot, bool purgePlaced) = tree.slotOf(ref.did);
            if (purgePlaced) tree.set(purgeSlot, bytes32(0));
            emit CredentialRevoked(ref.regimeHash, ref.did, "IK revoked");
            emit AttributeRegimeRootUpdated(ref.regimeHash, tree.root);
        }
        _purgeCursor[ikId] = cursor;
        emit IKPurgeProgress(ikId, cursor, refs.length);
    }

    /// @notice (processed, total): the purge is complete when processed == total.
    function purgeStatus(bytes32 ikId) external view returns (uint256 processed, uint256 total) {
        return (_purgeCursor[ikId], _issuedBy[ikId].length);
    }

    // ---------- credential issuance ----------

    /// @dev `expiresAt` (0 = no expiry) is FOLDED INTO the offchain-computed `commitment` and
    ///      re-derived in-circuit, which constrains session.validUntil <= expiresAt (GAP-H2): 
    ///      the leaf is the authoritative expiry; this stored copy is informational (a compromised
    ///      IK could store a divergent value, but the IK is already trusted for issuance content,
    ///      and a divergent leaf only hurts the holder: the proof fails). Must fit uint64 so the
    ///      in-circuit 64-bit comparator stays sound.
    function issueCredential(
        bytes32 regimeHash,
        bytes32 did,
        bytes32 commitment,
        uint256 expiresAt,
        bytes32 ikId,
        /// @param metadata Issuer-set, opaque, PUBLIC, and in no proof. bytes32(0) means "none".
        bytes32 metadata
    ) external {
        require(expiresAt < (1 << 64), "ITA: expiry exceeds uint64");
        IKEntry storage ik = _iks[ikId];
        require(ik.exists && !ik.revoked, "ITA: ik invalid");
        require(_isIKControl(ik, msg.sender), "ITA: not IK control");
        require(ik.regimeAuthorized[regimeHash], "ITA: ik not authorized for regime");
        require(supportedRegimes[regimeHash], "ITA: regime not adopted");
        require(GapLib.isField(did) && GapLib.isField(commitment), "ITA: not field");
        require(commitment != bytes32(0), "ITA: zero commitment");
        // Sybil (on-chain half): <=1 ACTIVE credential per (Attribute Regime, ITA) per DID.
        // A revoked credential (individual or IK purge) may be re-issued, otherwise a user whose
        // issuer was revoked would be locked out of the regime forever (GAP-H4 liveness).
        Credential storage existing = _credentials[regimeHash][did];
        require(existing.issuedAt == 0 || existing.revoked, "ITA: credential exists");

        PoseidonSparseTree.Tree storage tree = _regimeTrees[regimeHash];
        // Allocation-ordered, for the same reason the DID registry is: a credential tree keyed by
        // truncated DID collides on the birthday bound, and a collision here is an unissuable
        // credential rather than merely a retry.
        uint256 index = tree.allocate(did);
        require(tree.leafAt(index) == bytes32(0), "ITA: index occupied");

        _credentials[regimeHash][did] = Credential({
            commitment: commitment,
            issuerIKId: ikId,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            revoked: false,
            metadata: metadata
        });
        if (!_refSeen[ikId][regimeHash][did]) {             // GAP-H4: purgeable on IK revocation
            _refSeen[ikId][regimeHash][did] = true;
            _issuedBy[ikId].push(IssuanceRef(regimeHash, did));
        }
        tree.set(index, commitment);
        emit CredentialIssued(regimeHash, did, ikId, commitment, expiresAt, metadata);
        emit AttributeRegimeRootUpdated(regimeHash, tree.root);
    }

    /// @notice Issuer-or-admin revocation (canonical pattern). Zeroes the leaf → proofs fail.
    function revokeCredential(bytes32 regimeHash, bytes32 did, string calldata reason) external {
        Credential storage c = _credentials[regimeHash][did];
        require(c.issuedAt != 0 && !c.revoked, "ITA: no active credential");
        bool isIssuer = _iks[c.issuerIKId].exists && _isIKControl(_iks[c.issuerIKId], msg.sender);
        require(isIssuer || msg.sender == admin, "ITA: not issuer or admin");
        c.revoked = true;
        PoseidonSparseTree.Tree storage tree = _regimeTrees[regimeHash];
        (uint256 revokeSlot, bool revokePlaced) = tree.slotOf(did);
        require(revokePlaced, "ITA: not in tree");
        tree.set(revokeSlot, bytes32(0));
        emit CredentialRevoked(regimeHash, did, reason);
        emit AttributeRegimeRootUpdated(regimeHash, tree.root);
    }

    // ---------- views ----------

    /// @notice The Attribute Regime Root, pinned by the Session Manager as a ZK public witness.
    function getAttributeRegimeRoot(bytes32 regimeHash) external view returns (bytes32) {
        require(supportedRegimes[regimeHash], "ITA: regime not adopted");
        return _regimeTrees[regimeHash].root;
    }

    function getCredential(bytes32 regimeHash, bytes32 did) external view returns (Credential memory) {
        return _credentials[regimeHash][did];
    }

    /// @notice Whether the STORED credential record is active (exists, unrevoked, stored expiry
    ///         not passed). Informational: proof-validity is enforced by the LEAF: the circuit
    ///         constrains the leaf-folded expiresAt (GAP-H2), so if an IK stored a value that
    ///         diverges from the leaf, this view can disagree with what is actually provable.
    function isCredentialValid(bytes32 regimeHash, bytes32 did) external view returns (bool) {
        Credential storage c = _credentials[regimeHash][did];
        return c.issuedAt != 0 && !c.revoked && (c.expiresAt == 0 || c.expiresAt >= block.timestamp);
    }

    /// @notice Sibling path for the credential-membership witness (local/demo convenience).
    function getCredentialProof(bytes32 regimeHash, bytes32 did)
        external view returns (bytes32[] memory siblings, uint256 index)
    {
        PoseidonSparseTree.Tree storage tree = _regimeTrees[regimeHash];
        bool placed;
        (index, placed) = tree.slotOf(did);
        require(placed, "ITA: not in tree");
        siblings = tree.proof(index);
    }
}
