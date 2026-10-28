// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./libraries/GapLib.sol";

/**
 * @title IKRegistryBase
 * @notice In-anchor Identity-Keeper management (P0-7 option 1), extracted from IdentityAnchor so
 *         the anchor's credential/purge logic (GAP-H4) stays within the modularity budget.
 * @dev ikId = keccak(address(this), keccak(ikName)) mod P, ANCHOR-SCOPED (P0-7). A revoked IK's
 *      entry keeps `exists = true`, so its name can NEVER be re-registered: the ikId is
 *      tombstoned forever (prevents purge-state collisions on ikId reuse).
 */
abstract contract IKRegistryBase {
    struct IKEntry {
        bytes32 ikId;                // ITA-scoped
        string ikName;
        address[] controlKeys;       // simple-list mode (EOA or contract)
        address multiSigWallet;      // multi-sig mode (0 = simple-list)
        bytes publicKey;             // credential-bundle signing / referral routing
        mapping(bytes32 => bool) regimeAuthorized;
        bytes32[] authorizedRegimes;
        uint256 registeredAt;
        bool revoked;
        bool exists;
        string metadataURI;
    }

    address public admin;
    mapping(bytes32 => bool) public supportedRegimes;
    bytes32[] internal _supportedRegimeList;
    mapping(bytes32 => IKEntry) internal _iks;
    bytes32[] internal _ikIds;

    event IKRegistered(bytes32 indexed ikId, string ikName);
    event IKRevoked(bytes32 indexed ikId);
    event IKRegimesUpdated(bytes32 indexed ikId);
    event ControlKeysUpdated(bytes32 indexed ikId);
    event RegimeAdopted(bytes32 indexed regimeHash);

    modifier onlyAdmin() { require(msg.sender == admin, "ITA: not admin"); _; }

    function registerIK(
        string calldata ikName,
        address[] calldata controlKeys,
        address multiSigWallet,
        bytes calldata publicKey,
        bytes32[] calldata authorizedRegimes,
        string calldata metadataURI
    ) external onlyAdmin returns (bytes32 ikId) {
        require((controlKeys.length > 0) != (multiSigWallet != address(0)), "ITA: keys XOR multisig");
        require(publicKey.length > 0, "ITA: publicKey");
        ikId = GapLib.providerId(address(this), ikName);
        IKEntry storage ik = _iks[ikId];
        require(!ik.exists, "ITA: ik exists");
        ik.ikId = ikId;
        ik.ikName = ikName;
        ik.controlKeys = controlKeys;
        ik.multiSigWallet = multiSigWallet;
        ik.publicKey = publicKey;
        ik.registeredAt = block.timestamp;
        ik.exists = true;
        ik.metadataURI = metadataURI;
        for (uint256 i = 0; i < authorizedRegimes.length; i++) {
            require(supportedRegimes[authorizedRegimes[i]], "ITA: regime not adopted");
            ik.regimeAuthorized[authorizedRegimes[i]] = true;
            ik.authorizedRegimes.push(authorizedRegimes[i]);
        }
        _ikIds.push(ikId);
        emit IKRegistered(ikId, ikName);
    }

    /// @dev Regime scope is the ANCHOR's power (handoff/03 §5.2, changed from IK-editable).
    function updateIKRegimes(bytes32 ikId, bytes32[] calldata add, bytes32[] calldata remove) external onlyAdmin {
        IKEntry storage ik = _iks[ikId];
        require(ik.exists, "ITA: ik not found");
        for (uint256 i = 0; i < add.length; i++) {
            require(supportedRegimes[add[i]], "ITA: regime not adopted");
            if (!ik.regimeAuthorized[add[i]]) {
                ik.regimeAuthorized[add[i]] = true;
                ik.authorizedRegimes.push(add[i]);
            }
        }
        for (uint256 i = 0; i < remove.length; i++) {
            ik.regimeAuthorized[remove[i]] = false;
        }
        emit IKRegimesUpdated(ikId);
    }

    /// @dev Key rotation is the IK's power; ikId is unchanged.
    function updateControlKeys(bytes32 ikId, address[] calldata newKeys) external {
        IKEntry storage ik = _iks[ikId];
        require(ik.exists && !ik.revoked, "ITA: ik invalid");
        require(_isIKControl(ik, msg.sender), "ITA: not IK control");
        require(ik.multiSigWallet == address(0), "ITA: multisig mode");
        require(newKeys.length > 0, "ITA: empty keys");
        ik.controlKeys = newKeys;
        emit ControlKeysUpdated(ikId);
    }

    // ---------- views ----------

    function isIKControl(bytes32 ikId, address caller) external view returns (bool) {
        IKEntry storage ik = _iks[ikId];
        return ik.exists && !ik.revoked && _isIKControl(ik, caller);
    }

    function isIKAuthorizedForRegime(bytes32 ikId, bytes32 regimeHash) external view returns (bool) {
        IKEntry storage ik = _iks[ikId];
        return ik.exists && !ik.revoked && ik.regimeAuthorized[regimeHash];
    }

    function getIK(bytes32 ikId) external view returns (
        string memory ikName, address[] memory controlKeys, address multiSigWallet,
        bytes memory publicKey, bytes32[] memory authorizedRegimes, bool revoked, string memory metadataURI
    ) {
        IKEntry storage ik = _iks[ikId];
        require(ik.exists, "ITA: ik not found");
        return (ik.ikName, ik.controlKeys, ik.multiSigWallet, ik.publicKey, ik.authorizedRegimes, ik.revoked, ik.metadataURI);
    }

    function getSupportedRegimes() external view returns (bytes32[] memory) {
        return _supportedRegimeList;
    }

    function _isIKControl(IKEntry storage ik, address caller) internal view returns (bool) {
        if (ik.multiSigWallet != address(0)) return caller == ik.multiSigWallet;
        for (uint256 i = 0; i < ik.controlKeys.length; i++) {
            if (ik.controlKeys[i] == caller) return true;
        }
        return false;
    }
}
