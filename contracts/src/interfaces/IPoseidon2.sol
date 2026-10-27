// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

/**
 * @title IPoseidon2
 * @notice Interface for Poseidon hash function with 2 inputs
 * @dev Interface to the circomlibjs-generated Poseidon contract (contracts/bytecode/Poseidon2.bytecode)
 */
interface IPoseidon2 {
    /**
     * @notice Compute Poseidon hash of 2 inputs
     * @param input Array of 2 field elements
     * @return Poseidon hash result
     */
    function poseidon(bytes32[2] calldata input) external pure returns (bytes32);

    /**
     * @notice Compute Poseidon hash of 2 inputs (uint256 version)
     * @param input Array of 2 field elements
     * @return Poseidon hash result
     */
    function poseidon(uint256[2] calldata input) external pure returns (uint256);
}
