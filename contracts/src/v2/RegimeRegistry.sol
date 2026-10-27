// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./libraries/GapLib.sol";

/**
 * @title RegimeRegistry
 * @notice THIN regime type-definition registry per handoff/03 §3 (P1-14: kept thin, removable).
 * @dev A Regime is an IMMUTABLE type definition: the schema of an Attribute Credential
 *      (IDENTITY) or the enumerated Contract Classes (CLASSIFICATION).
 *
 *      THIS IS READ, and the header said the opposite until a review caught it. Both
 *      `IdentityAnchor.adoptRegime` and `ClassificationAnchor.adoptRegime` require
 *      `regimeExists(regimeHash)`, so an anchor cannot adopt a regime nobody defined. Circuits still
 *      take roots from the ITA/ORDB contracts and policies still pin `regimeHash` directly: that
 *      part was always true and is why this stayed thin.
 *
 *      WHAT THE GATE DOES NOT DO, since the prose around it has oversold this before. `proposeRegime`
 *      is permissionless and deployed with `proposalFee = 0`, so defining a regime costs one extra
 *      transaction: this stops an anchor adopting an UNDEFINED regime, not a determined party
 *      defining one. And `regimeExists` checks only that a definition was published, neither anchor
 *      checks `regimeType`, so an identity anchor can today adopt a CLASSIFICATION regime.
 *      Lifecycle fields remain advisory-only.
 */
contract RegimeRegistry {
    enum RegimeType { IDENTITY, CLASSIFICATION }

    struct Regime {
        bytes32 regimeHash;      // GapLib.regimeHash(regimeId, version), field-safe
        string regimeId;         // "standard-identity" | "investor-status" | "tokenized-securities"
        uint8 major; uint8 minor; uint8 patch;
        RegimeType regimeType;
        string name;
        string metadataURI;      // schema (IDENTITY: attribute fields; CLASSIFICATION: class codes)
        uint8 attributeCount;    // IDENTITY: number of attribute slots the credential carries
        address proposer;
        uint256 publishedAt;
        // advisory discovery metadata only, never a gate (see handoff/03 §3):
        bytes32 supersededBy;
    }

    uint256 public immutable proposalFee;
    address public immutable feeRecipient;

    mapping(bytes32 => Regime) private _regimes;
    bytes32[] private _all;

    event RegimeProposed(bytes32 indexed regimeHash, string regimeId, RegimeType regimeType, address proposer);
    event RegimeSuperseded(bytes32 indexed oldRegime, bytes32 indexed newRegime); // advisory

    constructor(uint256 _fee, address _feeRecipient) {
        proposalFee = _fee;
        feeRecipient = _fee > 0 ? _feeRecipient : address(0);
    }

    /// @notice Register a new immutable regime type definition. Permissionless.
    function proposeRegime(
        string calldata regimeId,
        uint8 major, uint8 minor, uint8 patch,
        RegimeType regimeType,
        string calldata name,
        string calldata metadataURI,
        uint8 attributeCount
    ) external payable returns (bytes32 rh) {
        require(msg.value >= proposalFee, "Regime: fee");
        rh = GapLib.regimeHash(regimeId, major, minor, patch);
        require(_regimes[rh].publishedAt == 0, "Regime: exists");
        if (regimeType == RegimeType.IDENTITY) {
            require(attributeCount > 0 && attributeCount <= 8, "Regime: attrs 1..8");
        }

        _regimes[rh] = Regime({
            regimeHash: rh,
            regimeId: regimeId,
            major: major, minor: minor, patch: patch,
            regimeType: regimeType,
            name: name,
            metadataURI: metadataURI,
            attributeCount: attributeCount,
            proposer: msg.sender,
            publishedAt: block.timestamp,
            supersededBy: bytes32(0)
        });
        _all.push(rh);
        if (proposalFee > 0 && feeRecipient != address(0)) {
            (bool ok,) = feeRecipient.call{value: msg.value}("");
            require(ok, "Regime: fee transfer");
        }
        emit RegimeProposed(rh, regimeId, regimeType, msg.sender);
    }

    /// @notice ADVISORY ONLY, a proposer hinting "prefer my v2". Gates nothing (handoff/03 §3).
    function supersede(bytes32 oldRegime, bytes32 newRegime) external {
        require(_regimes[oldRegime].proposer == msg.sender, "Regime: not proposer");
        require(_regimes[newRegime].publishedAt != 0, "Regime: new not found");
        _regimes[oldRegime].supersededBy = newRegime;
        emit RegimeSuperseded(oldRegime, newRegime);
    }

    // ---------- views ----------

    function regimeExists(bytes32 rh) external view returns (bool) {
        return _regimes[rh].publishedAt != 0;
    }

    function getRegime(bytes32 rh) external view returns (Regime memory) {
        require(_regimes[rh].publishedAt != 0, "Regime: not found");
        return _regimes[rh];
    }

    function getAllRegimes() external view returns (bytes32[] memory) {
        return _all;
    }
}
