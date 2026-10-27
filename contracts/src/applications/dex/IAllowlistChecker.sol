// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

/**
 * @notice The pluggable eligibility interface a permissioned AMM asks before a swap or an LP mint.
 * @dev Shaped to match the checker interface Uniswap v4 Permissioned Pools query through their
 *      PermissionsAdapter, which "doesn't keep the allowlist itself: it queries a checker contract
 *      the issuer writes and deploys, through a standard interface." That socket is the whole
 *      integration point, and it is a QUESTION, not a data structure: "may this account trade this
 *      token?" Every permissioned venue has to answer it, because the SEC's Innovation Exemption
 *      (Release 34-106402, 2026-09-17) requires a venue to establish standards governing access to
 *      its pools. What it does not prescribe is HOW.
 *
 *      The usual answer is a register of cleared wallets, which is the identity haystack the whole
 *      attribute-credential argument exists to remove. `GapAllowlistChecker` answers the same
 *      question from a live zero-knowledge session instead: same socket, no register, and nobody
 *      learns which human a wallet belongs to.
 */
interface IAllowlistChecker {
    /// @param account The end participant, NOT a router. See GapAllowlistChecker's note on this.
    /// @param token   The permissioned token being traded.
    /// @return flags  A bitfield of PermissionFlags; 0 means not permitted.
    function checkAllowlist(address account, address token) external view returns (uint8 flags);
}

library PermissionFlags {
    /// @notice May swap the token.
    uint8 internal constant SWAP_ALLOWED = 1 << 0;
    /// @notice May hold a liquidity position in it. Gated separately because an LP acquires
    ///         economic exposure to the security and may hold it indefinitely, so a venue may
    ///         reasonably demand a stricter policy of an LP than of a taker.
    uint8 internal constant LIQUIDITY_ALLOWED = 1 << 1;
}
