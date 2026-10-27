// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title RelayedGrantAuth
 * @notice EIP-712 authorization for a relayed `grantSessionFor`.
 *
 * @dev Extracted from SessionManager to keep that contract inside the project's 300-line limit.
 *      Pure/view only, it holds no state and decides nothing about sessions; it answers exactly
 *      one question: did `account` authorize THIS grant, over THIS proof, for THIS chain and
 *      contract, before the deadline?
 *
 *      Hand-rolled rather than inherited from OpenZeppelin's EIP712: OZ 5.4's
 *      EIP712/MessageHashUtils are pinned to ^0.8.24 and this tree compiles at 0.8.20. Only
 *      ECDSA (^0.8.20) is importable. The domain separator is recomputed per call, so a chain
 *      split can never replay a signature.
 *
 *      EIP-1271 is deliberately NOT supported. This signature is the stack's only
 *      proof-of-possession of the account key: the circuit proves the account address is a
 *      MEMBER of the spending-key tree, not that the prover holds its private key. Delegating
 *      that check to arbitrary mutable contract code would let a permissive `isValidSignature`
 *      silently downgrade the GAP-H6 recipient gate, and would add an untrusted external call to
 *      the grant path. Contract accounts use `grantSession` directly, where msg.sender is the
 *      proof of possession.
 */
library RelayedGrantAuth {
    /// @notice Scalars of a relayed grant. Grouped into a struct because the flat parameter list
    ///         is stack-too-deep at 0.8.20 without via_ir, which this tree does not enable.
    struct SessionGrant {
        address account;
        bytes32 policyId;
        uint32 policyVersion;
        uint64 validUntil;
        uint256 deadline;
    }

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _NAME_HASH = keccak256("GAP SessionManager");
    bytes32 private constant _VERSION_HASH = keccak256("2");

    /// @notice The relayed-grant struct. `pubDigest` covers the whole 19-slot public-input array
    ///         (so account/nonce/roots/commitments are all bound) and `ciphertextDigest` covers the
    ///         off-circuit ECIES blob, which the PROOF does not bind, without it a relayer could
    ///         swap in garbage and force the TM attestation to fail.
    bytes32 internal constant RELAYED_GRANT_TYPEHASH = keccak256(
        "RelayedSessionGrant(address account,bytes32 policyId,uint32 policyVersion,uint64 validUntil,"
        "bytes32 pubDigest,bytes32 ciphertextDigest,uint256 sessionNonce,uint256 deadline)"
    );

    /// @notice EIP-712 domain separator, binds chainId and the verifying contract.
    /// @dev These are `internal`, so they inline into the calling contract and `address(this)`
    ///      is that contract: the verifying contract never needs to be passed in.
    function domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(_EIP712_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, address(this))
        );
    }

    /// @notice The exact digest a relayed grant must be signed over (wallet/relayer helper).
    ///         `pubDigest` MUST be `keccak256(abi.encode(pub))` over the full 19-slot array and
    ///         `ciphertextDigest` `keccak256(ciphertext)`; `nonce` is `sessionNonce(account)`.
    function digest(
        SessionGrant memory g,
        bytes32 pubDigest,
        bytes32 ciphertextDigest,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                RELAYED_GRANT_TYPEHASH,
                g.account,
                g.policyId,
                g.policyVersion,
                g.validUntil,
                pubDigest,
                ciphertextDigest,
                nonce,
                g.deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Reverts unless `grant.account` signed exactly this grant, over this proof and
    ///         ciphertext, for this chain and contract, at this nonce, before the deadline.
    function requireAuthorized(
        SessionGrant calldata grant,
        uint256[19] calldata pub,
        bytes calldata ciphertext,
        bytes calldata signature,
        uint256 nonce
    ) internal view {
        require(block.timestamp <= grant.deadline, "SM: grant deadline passed");
        bytes32 d = digest(
            grant,
            keccak256(abi.encode(pub)),
            keccak256(ciphertext),
            nonce // replay: the caller bumps this on install, burning this signature
        );
        // tryRecover rejects malleable (high-s), bad-v and wrong-length signatures explicitly;
        // the signer==account check additionally rejects the address(0) recovery.
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(d, signature);
        require(err == ECDSA.RecoverError.NoError, "SM: malformed grant signature");
        require(signer != address(0) && signer == grant.account, "SM: grant signer mismatch");
    }
}
