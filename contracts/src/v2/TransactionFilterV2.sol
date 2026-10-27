// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./SessionManager.sol";

/**
 * @title TransactionFilterV2
 * @notice Per-contract, per-function filter per handoff/03 §10. Drastically simpler than v2.5:
 *         the user-side check is ONE Session-Manager lookup (unexpired session for a required
 *         policy) and the contract-side check is ONE Contract-Session lookup. All attribute /
 *         ITA / ORDB / predicate work was proven in-circuit at session grant (P0-6, P1-8).
 * @dev Deployed one-per-monitored-contract; config keyed by function selector.
 */
contract TransactionFilterV2 {
    struct UserConfig {
        bytes32[] necessaryPolicies; // that's it: each policy self-describes its roots (P0-6)
    }

    // GAP-H6 recipient gating is TRI-STATE (internal review finding): UNSET fails closed (a gated selector
    // must take an explicit recipient decision), DISABLED is intentionally open (sender-only
    // gating), ENABLED requires a receiving session for every listed policy.
    enum RecipientGating { UNSET, DISABLED, ENABLED }

    struct RecipientConfig {
        RecipientGating mode;
        bytes32[] policies;          // the "receiving" policies (long/short-expiry User Sessions)
    }

    address public admin;                 // the monitored contract's operator (its TM, typically)
    address public gatedContract;         // the contract this TF gates (== pseudonym scope); internal review finding #3
    SessionManager public immutable sessionManager;

    mapping(bytes4 => UserConfig) private _userCfg;
    mapping(bytes4 => bool) private _configured; // default-DENY until a selector is explicitly set (internal review)
    mapping(bytes4 => RecipientConfig) private _recipientCfg;
    mapping(bytes4 => SessionManager.ContractRequirement[]) private _contractCfg;

    event UserConfigSet(bytes4 indexed selector, bytes32[] policies);
    event RecipientConfigSet(bytes4 indexed selector, RecipientGating mode, bytes32[] policies);
    event ContractConfigSet(bytes4 indexed selector, uint256 requirementCount);
    event GatedContractSet(address gatedContract);

    modifier onlyAdmin() { require(msg.sender == admin, "TF: not admin"); _; }

    constructor(address _admin, address _sessionManager) {
        require(_admin != address(0) && _sessionManager != address(0), "TF: zero addr");
        admin = _admin;
        sessionManager = SessionManager(_sessionManager);
    }

    /// @notice The contract this TF gates, sessions must have been proven for THIS address.
    function setGatedContract(address c) external onlyAdmin {
        gatedContract = c;
        emit GatedContractSet(c);
    }

    function setUserConfig(bytes4 selector, bytes32[] calldata policies) external onlyAdmin {
        require(policies.length > 0, "TF: empty policy set"); // gated selectors need >=1 policy (internal review)
        _userCfg[selector].necessaryPolicies = policies;
        _configured[selector] = true;
        emit UserConfigSet(selector, policies);
    }

    /// @notice GAP-H6: recipient-side gating decision for a selector. `enabled = false` records an
    ///         EXPLICIT sender-only choice; `enabled = true` requires a receiving session for every
    ///         listed policy. Leaving a gated selector UNSET fails closed in checkRecipient.
    function setRecipientConfig(bytes4 selector, bool enabled, bytes32[] calldata policies) external onlyAdmin {
        RecipientConfig storage rc = _recipientCfg[selector];
        if (enabled) {
            require(policies.length > 0, "TF: empty recipient policy set");
            rc.mode = RecipientGating.ENABLED;
            rc.policies = policies;
        } else {
            require(policies.length == 0, "TF: policies with disable");
            rc.mode = RecipientGating.DISABLED;
            delete rc.policies;
        }
        emit RecipientConfigSet(selector, rc.mode, rc.policies);
    }

    function setContractConfig(bytes4 selector, SessionManager.ContractRequirement[] calldata reqs)
        external onlyAdmin
    {
        delete _contractCfg[selector];
        for (uint256 i = 0; i < reqs.length; i++) {
            _contractCfg[selector].push(reqs[i]);
        }
        emit ContractConfigSet(selector, reqs.length);
    }

    /**
     * @notice The whole gate. `user` = EOA argument; `counterparty` = contract argument (0 = none).
     *         ALL requirements must pass.
     */
    function check(bytes4 selector, address user, address counterparty) external view returns (bool) {
        // 0. Default-DENY: an unconfigured selector is never open (internal review finding).
        if (!_configured[selector]) return false;
        require(gatedContract != address(0), "TF: gatedContract unset");
        // 1. User Session valid, single validUntil compare per required policy, AND the session
        //    must have been proven FOR this gated contract (internal review finding: no cross-contract reuse).
        //    A CONTRACT holding the security: an AMM pool, a custodian, cannot hold a user
        //    session: the grant path requires `pub[0] == msg.sender` over a spending-set membership
        //    proof, which a pool has no DID or salt to produce. The GAP whitepaper §7 puts the
        //    answer plainly: "in each token transfer the Transaction Filter checks that the 'to' and
        //    'from' addresses have the appropriate session. The user has already started their User
        //    Session, and the AMM already has an active Contract Session via their 'Compliant DEX'
        //    Classification Credential." So the sender side tries the same two routes the recipient
        //    side already tries, in the same order. Opt-in per selector: `_contractCfg` is empty
        //    until an admin calls `setContractConfig`, so no contract passes by default and this
        //    changes nothing for any selector that does not configure it.
        bytes32[] storage policies = _userCfg[selector].necessaryPolicies;
        bool sessionsOk = true;
        for (uint256 i = 0; i < policies.length; i++) {
            if (!sessionManager.hasValidSession(user, policies[i], gatedContract)) {
                sessionsOk = false;
                break;
            }
        }
        if (!sessionsOk) {
            SessionManager.ContractRequirement[] storage senderReqs = _contractCfg[selector];
            if (senderReqs.length == 0) return false;
            for (uint256 i = 0; i < senderReqs.length; i++) {
                if (!sessionManager.hasValidContractSession(user, senderReqs[i])) return false;
            }
        }
        // 2. Contract Session: one Session-Manager lookup per requirement (P1-14).
        if (counterparty != address(0)) {
            SessionManager.ContractRequirement[] storage reqs = _contractCfg[selector];
            for (uint256 i = 0; i < reqs.length; i++) {
                if (!sessionManager.hasValidContractSession(counterparty, reqs[i])) return false;
            }
        }
        return true;
    }

    /**
     * @notice GAP-H6 recipient gate: `to` passes with an unexpired, attested receiving session
     *         for EVERY configured receiving policy (proven FOR this gated contract), OR, for
     *         contract recipients like pools/custodians, which cannot hold user sessions, with
     *         the selector's Contract-Session requirements, if any are configured (internal review finding:
     *         this route must be reachable from plain transfers). Fails closed on an UNSET
     *         config. EOA-vs-contract cannot be reliably distinguished on-chain (EIP-7702 /
     *         pre-deploys), so both routes are simply tried, either satisfies the gate.
     */
    function checkRecipient(bytes4 selector, address recipient) external view returns (bool) {
        RecipientConfig storage rc = _recipientCfg[selector];
        if (rc.mode == RecipientGating.UNSET) return false;    // fail closed until configured
        if (rc.mode == RecipientGating.DISABLED) return true;  // explicit sender-only choice
        require(gatedContract != address(0), "TF: gatedContract unset");
        bool sessionsOk = true;
        for (uint256 i = 0; i < rc.policies.length; i++) {
            if (!sessionManager.hasValidSession(recipient, rc.policies[i], gatedContract)) {
                sessionsOk = false;
                break;
            }
        }
        if (sessionsOk) return true;
        // contract-recipient route: all of the selector's contract-session requirements
        SessionManager.ContractRequirement[] storage reqs = _contractCfg[selector];
        if (reqs.length == 0) return false;
        for (uint256 i = 0; i < reqs.length; i++) {
            if (!sessionManager.hasValidContractSession(recipient, reqs[i])) return false;
        }
        return true;
    }

    function getUserConfig(bytes4 selector) external view returns (bytes32[] memory) {
        return _userCfg[selector].necessaryPolicies;
    }

    function getRecipientConfig(bytes4 selector) external view returns (RecipientGating mode, bytes32[] memory policies) {
        RecipientConfig storage rc = _recipientCfg[selector];
        return (rc.mode, rc.policies);
    }

    function getContractConfig(bytes4 selector)
        external view returns (SessionManager.ContractRequirement[] memory)
    {
        return _contractCfg[selector];
    }
}
