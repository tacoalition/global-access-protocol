// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

/**
 * @title GapLib
 * @notice Shared constants + field-safe id helpers for the GAP v2 stack.
 * @dev SPIKE-A IMPLEMENTATION CHOICE (documented in the handoff spec §4, full stack, not in this repository):
 *      keccak-derived identifiers are reduced mod the BN254 scalar field AT THE SOURCE
 *      (`toField`) instead of being carried as 128-bit limbs in-circuit. Every id that
 *      enters a Poseidon preimage (regimeHash, ikId, ccId, DID) is < P by construction,
 *      with ~254-bit collision resistance retained.
 */
library GapLib {
    /// @notice BN254 scalar field modulus (circom / Groth16 field).
    uint256 internal constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Domain tag for the Attribute Credential leaf: keccak("GAP_ATTR_CRED_V3") mod P.
    /// @dev V2 folded `expiresAt` into the leaf (GAP-H2). V3 widens `attrsHash` from Poseidon(2)
    ///      to Poseidon(4), four attributes per regime instead of two, so the bump
    ///      domain-separates V2 leaves from V3 ones.
    function credTag() internal pure returns (bytes32) {
        return toField(keccak256("GAP_ATTR_CRED_V3"));
    }

    /// @notice Reduce a keccak output into the BN254 scalar field.
    function toField(bytes32 x) internal pure returns (bytes32) {
        return bytes32(uint256(x) % P);
    }

    function isField(bytes32 x) internal pure returns (bool) {
        return uint256(x) < P;
    }

    /// @notice Anchor-scoped provider id (P0-7): keccak(anchor, keccak(name)) mod P.
    function providerId(address anchor, string memory name) internal pure returns (bytes32) {
        return toField(keccak256(abi.encodePacked(anchor, keccak256(bytes(name)))));
    }

    /// @notice Regime hash: keccak(regimeId, versionMajor.minor.patch) mod P.
    function regimeHash(string memory regimeId, uint8 major, uint8 minor, uint8 patch)
        internal pure returns (bytes32)
    {
        return toField(keccak256(abi.encodePacked(regimeId, major, minor, patch)));
    }

    /// @notice Stable policy id (NOT content-addressed): keccak(owner, name).
    function policyId(address owner, string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, name));
    }
}
