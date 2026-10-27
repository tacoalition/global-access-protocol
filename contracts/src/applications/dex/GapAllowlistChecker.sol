// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import {IAllowlistChecker, PermissionFlags} from "./IAllowlistChecker.sol";

interface ICheckerSessionManager {
    function hasValidSession(address account, bytes32 policyId, address gatedContract)
        external view returns (bool);
}

/**
 * @title GapAllowlistChecker
 * @notice Answers a permissioned pool's eligibility question from a GAP session, not from a list.
 *
 * @dev WHAT THIS REPLACES. The naive implementation of `IAllowlistChecker` is
 *      `mapping(address => bool)`, maintained by an issuer that collected documents and knows which
 *      human each wallet is. That register is a standing liability and the thing an
 *      attribute-credential scheme exists to delete. This contract answers the identical question
 *      with `hasValidSession`: the wallet holds an unexpired, TM-attested session it obtained by
 *      proving in zero knowledge that its attributes satisfy a published policy. No register, no
 *      documents, and no wallet-to-identity link anywhere in the path.
 *
 *      WHAT IT DOES NOT HIDE, stated plainly so nobody oversells it. Session grants are public and
 *      keyed by the account, so the SET of eligible addresses is publicly enumerable, see
 *      docs/ON_CHAIN_DISCLOSURE.md. What the proof protects is the wallet-to-DID link and
 *      the attribute VALUES, not the existence of eligibility.
 *
 *      SWAP vs LIQUIDITY are two policies, not one. A taker's exposure ends when the swap settles;
 *      an LP holds the security's economics for as long as the position is open, so a venue may
 *      demand more of them. Wiring both to the same policyId is a deployment choice, not a
 *      shortcut this contract takes for you.
 *
 *      SCOPE, and why `sessionScope` is not the token. `hasValidSession` is asked about the session's
 *      `gatedContract` (public signal 15), which is also the ORDB's monitored contract and therefore
 *      the pseudonym scope. Point it at the DEX to make swap eligibility its own scope with its own
 *      flag surface; point it at a shared anchor to make one session and one flag cover several
 *      venues. That reach is the deployment's decision: this contract only asks the question.
 *
 *      FAIL CLOSED. Every read is a low-level staticcall that yields `false` on revert, on a short
 *      return, or on any word that is not exactly 1. A reverting or absent session manager denies;
 *      it never admits. The primitive is `DsiFundAllowlistAdapter._readBool`, reused deliberately
 *      rather than re-derived.
 */
contract GapAllowlistChecker is IAllowlistChecker {
    /// @notice The permissioned token this checker speaks for. Any other token returns 0.
    address public immutable configuredToken;
    /// @notice The session's `gatedContract`, see the scope note above.
    address public immutable sessionScope;
    address public immutable sessionManager;
    /// @notice Policy a taker must hold a session under.
    bytes32 public immutable swapPolicyId;
    /// @notice Policy a liquidity provider must hold a session under. May equal `swapPolicyId`.
    bytes32 public immutable liquidityPolicyId;

    error CheckerZeroAddress();
    error CheckerAddressHasNoCode(address target);
    error CheckerUnsetPolicy();

    constructor(
        address configuredToken_,
        address sessionScope_,
        address sessionManager_,
        bytes32 swapPolicyId_,
        bytes32 liquidityPolicyId_
    ) {
        if (
            configuredToken_ == address(0) || sessionScope_ == address(0) || sessionManager_ == address(0)
        ) revert CheckerZeroAddress();
        if (configuredToken_.code.length == 0) revert CheckerAddressHasNoCode(configuredToken_);
        if (sessionManager_.code.length == 0) revert CheckerAddressHasNoCode(sessionManager_);
        if (swapPolicyId_ == bytes32(0) || liquidityPolicyId_ == bytes32(0)) revert CheckerUnsetPolicy();
        configuredToken = configuredToken_;
        sessionScope = sessionScope_;
        sessionManager = sessionManager_;
        swapPolicyId = swapPolicyId_;
        liquidityPolicyId = liquidityPolicyId_;
    }

    /// @inheritdoc IAllowlistChecker
    function checkAllowlist(address account, address token) external view returns (uint8 flags) {
        if (account == address(0) || token != configuredToken) return 0;
        if (_sessionValid(account, swapPolicyId)) flags |= PermissionFlags.SWAP_ALLOWED;
        if (_sessionValid(account, liquidityPolicyId)) flags |= PermissionFlags.LIQUIDITY_ALLOWED;
    }

    function maySwap(address account) external view returns (bool) {
        return account != address(0) && _sessionValid(account, swapPolicyId);
    }

    function mayProvideLiquidity(address account) external view returns (bool) {
        return account != address(0) && _sessionValid(account, liquidityPolicyId);
    }

    function _sessionValid(address account, bytes32 policyId) private view returns (bool) {
        return _readBool(
            sessionManager,
            abi.encodeCall(ICheckerSessionManager.hasValidSession, (account, policyId, sessionScope))
        );
    }

    /// @dev Verbatim from DsiFundAllowlistAdapter: a short return, a revert, or any word that is
    ///      not exactly 1 all read as "not permitted".
    function _readBool(address target, bytes memory callData) private view returns (bool) {
        (bool success, bytes memory result) = target.staticcall(callData);
        if (!success || result.length != 32) return false;
        uint256 value;
        assembly {
            value := mload(add(result, 0x20))
        }
        return value == 1;
    }
}
