// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./RegimeRegistry.sol";
import "./libraries/GapLib.sol";

/**
 * @title ClassificationAnchor (CTA Contract)
 * @notice Per-CTA anchor per handoff/03 §6 (P0-7 option 1): manages its OWN Contract Certifiers
 *         in-anchor. No ClassificationAnchorRegistry exists: a CTA is deployed directly and
 *         identified by this contract's address; discovery/reputation are offchain.
 * @dev ccId = keccak(address(this), keccak(ccName)) mod P, CTA-scOPED (reviewer L749).
 *      CC principals may be EOAs or contracts (control keys are plain addresses).
 */
contract ClassificationAnchor {
    struct CCEntry {
        bytes32 ccId;
        string ccName;
        address[] controlKeys;      // simple-list mode
        address multiSigWallet;     // multi-sig mode (0 = simple-list)
        mapping(bytes32 => bool) regimeAuthorized;
        bytes32[] authorizedRegimes;
        uint256 registeredAt;
        bool revoked;
        bool exists;
        string metadataURI;
    }

    address public admin;
    string public metadataURI; // CTA reputation/ToS pointer (self-cert posture documented here)

    mapping(bytes32 => CCEntry) private _ccs;
    bytes32[] private _ccIds;
    mapping(bytes32 => bool) public supportedRegimes; // Classification Regimes this zone runs
    bytes32[] private _supportedRegimeList;

    event CCRegistered(bytes32 indexed ccId, string ccName);
    event CCRevoked(bytes32 indexed ccId);
    event CCRegimesUpdated(bytes32 indexed ccId);
    event ControlKeysUpdated(bytes32 indexed ccId);
    event RegimeAdopted(bytes32 indexed regimeHash);
    event RegimeDropped(bytes32 indexed regimeHash);

    modifier onlyAdmin() { require(msg.sender == admin, "CTA: not admin"); _; }

    /// The shared regime registry this anchor's adoptions are checked against, same rule as the
    /// identity anchor, because a CLASSIFICATION regime invented per-anchor is no more a shared fact
    /// than an attribute regime is.
    address public immutable regimeRegistry;

    constructor(address _admin, string memory _metadataURI, address _regimeRegistry) {
        require(_admin != address(0), "CTA: zero admin");
        require(_regimeRegistry != address(0), "CTA: regime registry");
        admin = _admin;
        metadataURI = _metadataURI;
        regimeRegistry = _regimeRegistry;
    }

    /// @dev See `IdentityAnchor.adoptRegime`: the registry was advisory-only until an October 2026
    ///      review pointed out that nothing read it. Both anchors enforce it now, or neither does.
    function adoptRegime(bytes32 regimeHash) external onlyAdmin {
        require(RegimeRegistry(regimeRegistry).regimeExists(regimeHash), "CTA: regime not registered");
        if (!supportedRegimes[regimeHash]) {
            supportedRegimes[regimeHash] = true;
            _supportedRegimeList.push(regimeHash);
            emit RegimeAdopted(regimeHash);
        }
    }

    function dropRegime(bytes32 regimeHash) external onlyAdmin {
        supportedRegimes[regimeHash] = false;
        emit RegimeDropped(regimeHash);
    }

    /// @notice Register a CC (self-cert = registering a project's own deployer key as a CC).
    function registerCC(
        string calldata ccName,
        address[] calldata controlKeys,
        address multiSigWallet,
        bytes32[] calldata authorizedRegimes,
        string calldata cMetadataURI
    ) external onlyAdmin returns (bytes32 ccId) {
        require((controlKeys.length > 0) != (multiSigWallet != address(0)), "CTA: keys XOR multisig");
        ccId = GapLib.providerId(address(this), ccName);
        CCEntry storage cc = _ccs[ccId];
        require(!cc.exists, "CTA: cc exists");
        cc.ccId = ccId;
        cc.ccName = ccName;
        cc.controlKeys = controlKeys;
        cc.multiSigWallet = multiSigWallet;
        cc.registeredAt = block.timestamp;
        cc.exists = true;
        cc.metadataURI = cMetadataURI;
        for (uint256 i = 0; i < authorizedRegimes.length; i++) {
            require(supportedRegimes[authorizedRegimes[i]], "CTA: regime not adopted");
            cc.regimeAuthorized[authorizedRegimes[i]] = true;
            cc.authorizedRegimes.push(authorizedRegimes[i]);
        }
        _ccIds.push(ccId);
        emit CCRegistered(ccId, ccName);
    }

    /// @dev CC revocation is NON-RETROACTIVE (handoff/03 §9.3): certifications it issued remain
    ///      valid until explicitly revoked via ClassificationContract.revokeClassification.
    function revokeCC(bytes32 ccId) external onlyAdmin {
        require(_ccs[ccId].exists, "CTA: cc not found");
        _ccs[ccId].revoked = true;
        emit CCRevoked(ccId);
    }

    function updateCCRegimes(bytes32 ccId, bytes32[] calldata add, bytes32[] calldata remove) external onlyAdmin {
        CCEntry storage cc = _ccs[ccId];
        require(cc.exists, "CTA: cc not found");
        for (uint256 i = 0; i < add.length; i++) {
            require(supportedRegimes[add[i]], "CTA: regime not adopted");
            if (!cc.regimeAuthorized[add[i]]) {
                cc.regimeAuthorized[add[i]] = true;
                cc.authorizedRegimes.push(add[i]);
            }
        }
        for (uint256 i = 0; i < remove.length; i++) {
            cc.regimeAuthorized[remove[i]] = false;
        }
        emit CCRegimesUpdated(ccId);
    }

    function updateControlKeys(bytes32 ccId, address[] calldata newKeys) external {
        CCEntry storage cc = _ccs[ccId];
        require(cc.exists && !cc.revoked, "CTA: cc invalid");
        require(_isCCControl(cc, msg.sender), "CTA: not CC control");
        require(cc.multiSigWallet == address(0), "CTA: multisig mode");
        require(newKeys.length > 0, "CTA: empty keys");
        cc.controlKeys = newKeys;
        emit ControlKeysUpdated(ccId);
    }

    // ---------- views (consumed by ClassificationContract.addClassification) ----------

    function isCCControl(bytes32 ccId, address caller) external view returns (bool) {
        CCEntry storage cc = _ccs[ccId];
        return cc.exists && !cc.revoked && _isCCControl(cc, caller);
    }

    function isCCAuthorizedForRegime(bytes32 ccId, bytes32 regimeHash) external view returns (bool) {
        CCEntry storage cc = _ccs[ccId];
        return cc.exists && !cc.revoked && cc.regimeAuthorized[regimeHash];
    }

    function getCC(bytes32 ccId) external view returns (
        string memory ccName, address[] memory controlKeys, address multiSigWallet,
        bytes32[] memory authorizedRegimes, bool revoked, string memory cMetadataURI
    ) {
        CCEntry storage cc = _ccs[ccId];
        require(cc.exists, "CTA: cc not found");
        return (cc.ccName, cc.controlKeys, cc.multiSigWallet, cc.authorizedRegimes, cc.revoked, cc.metadataURI);
    }

    function getSupportedRegimes() external view returns (bytes32[] memory) {
        return _supportedRegimeList;
    }

    function _isCCControl(CCEntry storage cc, address caller) private view returns (bool) {
        if (cc.multiSigWallet != address(0)) return caller == cc.multiSigWallet;
        for (uint256 i = 0; i < cc.controlKeys.length; i++) {
            if (cc.controlKeys[i] == caller) return true;
        }
        return false;
    }
}
