// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./ClassificationAnchor.sol";

/**
 * @title ClassificationContract
 * @notice Singleton Classification-Credential store per handoff/03 §7: the map
 *         `contract address → Classification[]` that BACKS the Session Manager's
 *         Contract Sessions (P1-14). Reads CC authorization from the issuing CTA contract.
 * @dev Captures certifiedCodeHash (EXTCODEHASH) at certification for upgrade detection.
 *      There is no "CTA not revoked" check: no registry exists to revoke a CTA; a TF simply
 *      stops accepting that CTA address (handoff/03 §7.2).
 */
contract ClassificationContract {
    struct Classification {
        address cta;                 // authorizing CTA (ClassificationAnchor address = CTA ID)
        bytes32 regimeHash;          // Classification Regime
        uint256 class;               // Contract Class binary code (e.g. 1=TOKENIZED_SECURITY, 2=DEX)
        bytes32 ccId;                // issuing CC (CTA-scoped)
        uint256 issuedAt;
        bytes32 certificationHash;   // audit-report pointer
        bytes32 certifiedCodeHash;   // EXTCODEHASH at certification, invalidation anchor
        address contractSponsor;     // primary code liability (handoff/07 §6)
        bytes metadata;
        bool revoked;
        /**
         * THE CERTIFIER ASSERTS this target has no upgrade path: no proxy, no delegatecall to
         * mutable code, no selfdestruct-and-recreate. It is an ASSERTION, not a measurement, and it
         * has to be: `certifiedCodeHash` pins the bytecode AT THIS ADDRESS, and for a proxy that
         * bytecode never changes when the implementation behind it does. The EVM gives no way to
         * check, `SLOAD` reads only the executing contract's storage, so this contract cannot read
         * a proxy's implementation slot, and anything the proxy chooses to expose it can lie about.
         *
         * So the honest division is: the certifier states it here, a venue REQUIRES it via
         * ContractRequirement.requireImmutableCode, and `maxAge` bounds how long any assertion is
         * trusted. See docs/CONTRACT_UPGRADES.md.
         */
        bool codeIsImmutable;
    }

    mapping(address => Classification[]) private _classifications;

    event ClassificationAdded(address indexed target, address indexed cta, bytes32 indexed regimeHash, uint256 class, bytes32 ccId, uint256 idx);
    event ClassificationRevoked(address indexed target, uint256 idx);

    function addClassification(
        address target,
        address cta,
        bytes32 regimeHash,
        uint256 class,
        bytes32 ccId,
        bytes32 certificationHash,
        address contractSponsor,
        bytes calldata metadata,
        /// @param codeIsImmutable The certifier's assertion that this target has no upgrade path.
        bool codeIsImmutable
    ) external returns (uint256 idx) {
        ClassificationAnchor anchor = ClassificationAnchor(cta);
        require(anchor.isCCControl(ccId, msg.sender), "CLS: not CC control");
        require(anchor.isCCAuthorizedForRegime(ccId, regimeHash), "CLS: cc not authorized for regime");
        bytes32 codeHash = target.codehash;
        require(codeHash != bytes32(0), "CLS: target has no code");
        // no duplicate (cta, regime, class) active entry for the target
        Classification[] storage list = _classifications[target];
        for (uint256 i = 0; i < list.length; i++) {
            Classification storage c = list[i];
            if (!c.revoked && c.cta == cta && c.regimeHash == regimeHash && c.class == class) {
                revert("CLS: duplicate classification");
            }
        }
        idx = list.length;
        list.push(Classification({
            cta: cta,
            regimeHash: regimeHash,
            class: class,
            ccId: ccId,
            issuedAt: block.timestamp,
            certificationHash: certificationHash,
            certifiedCodeHash: codeHash,
            codeIsImmutable: codeIsImmutable,
            contractSponsor: contractSponsor,
            metadata: metadata,
            revoked: false
        }));
        emit ClassificationAdded(target, cta, regimeHash, class, ccId, idx);
    }

    /// @notice Issuing CC or the CTA admin may revoke (bulk cleanup of a rogue CC's certs).
    function revokeClassification(address target, uint256 idx) external {
        Classification storage c = _classifications[target][idx];
        require(!c.revoked, "CLS: already revoked");
        ClassificationAnchor anchor = ClassificationAnchor(c.cta);
        bool isIssuer = anchor.isCCControl(c.ccId, msg.sender);
        bool isCtaAdmin = anchor.admin() == msg.sender;
        require(isIssuer || isCtaAdmin, "CLS: not issuer or CTA admin");
        c.revoked = true;
        emit ClassificationRevoked(target, idx);
    }

    // ---------- views (backing Contract Sessions, handoff/03 §9.3) ----------

    function getClassification(address target, uint256 idx) external view returns (Classification memory) {
        return _classifications[target][idx];
    }

    function classificationCount(address target) external view returns (uint256) {
        return _classifications[target].length;
    }

    /// @notice Live validity: not revoked ∧ (optionally) code unchanged since certification.
    function isClassificationValid(
        address target,
        uint256 idx,
        bool requireCodeMatch,
        uint256 maxAge,
        bool requireImmutableCode
    )
        external view returns (bool)
    {
        Classification[] storage list = _classifications[target];
        if (idx >= list.length) return false;
        Classification storage c = list[idx];
        if (c.revoked) return false;
        if (requireCodeMatch && target.codehash != c.certifiedCodeHash) return false;
        if (maxAge != 0 && block.timestamp > c.issuedAt + maxAge) return false;
        if (requireImmutableCode && !c.codeIsImmutable) return false;
        return true;
    }
}
