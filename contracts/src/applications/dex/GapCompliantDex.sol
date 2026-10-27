// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {TransactionFilterV2} from "../../v2/TransactionFilterV2.sol";

interface IErc20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @title GapCompliantDex
 * @notice A permissioned constant-product AMM for one gated security against one cash token.
 *
 * @dev WHY THIS EXISTS RATHER THAN A HOOK ON A SHARED POOL. The SEC's Innovation Exemption
 *      (Release 34-106402, 2026-09-17) covers AMM pools "for permissioned participants", so the
 *      regulated object is a permissioned pool, not a general one. And the GAP whitepaper §7
 *      already specifies the shape: three contracts each with their own Transaction Filter,
 *      Transaction Monitor and Onchain Risk Database, where "the Transaction Monitor for the AMM
 *      would be performing market integrity screening, scanning for behaviours such as wash trading
 *      or sandwich attacks": a different job from the tokens' AML/CFT. Hence `transactionFilter`
 *      here is the DEX's OWN filter over the DEX's own ORDB, not the token's.
 *
 *      THE TRADER IS `msg.sender`, WHICH IS THE POINT. On a shared singleton the pool sees the
 *      router, not the person, and `beforeSwap`'s `sender` argument cannot be trusted as an
 *      identity; passing the trader in unauthenticated hook data invites impersonation. Here the
 *      entry points ARE the trade, so there is no router in between and no identity to forge.
 *
 *      THE POOL HOLDS THE SECURITY, so it must itself be a lawful holder. It cannot hold a user
 *      session: the grant path needs a spending-set membership proof it has no DID or salt to
 *      make, so it holds a Contract Session from a Classification Credential, exactly as the
 *      whitepaper describes for its "Compliant DEX" class. That is configured on the TOKEN's filter
 *      at deploy (`setContractConfig` + `registerContractSession`); nothing here can grant it.
 *
 *      LP POSITIONS ARE NON-TRANSFERABLE BALANCES, NOT A TOKEN, and that is a compliance decision
 *      rather than a simplification. A transferable LP receipt is an unregistered wrapper around
 *      the security: an ineligible party could buy the receipt and hold the economics without ever
 *      touching the gated token. The whitepaper names that failure directly, "if this token is
 *      deposited into an ERC-20 contract or something similar, these controls no longer apply to the
 *      wrapper". With no wrapper to transfer there is nothing to look through.
 *
 *      SWAP OUTPUT GOES TO `msg.sender`, never to a caller-named recipient. The token's own
 *      recipient gate would catch a non-compliant destination anyway, but refusing to accept one
 *      removes the question instead of relying on a second gate to answer it.
 *
 *      WHAT THIS IS NOT. Reserves are tracked internally, so a direct token transfer into this
 *      contract is ignored rather than counted. There is no price oracle, no flash accounting and
 *      no multi-hop routing; this is a reference venue for demonstrating compliant settlement, not
 *      a production exchange.
 *
 *      TOKEN ASSUMPTIONS, which are load-bearing. Both legs must be plain ERC-20s: no transfer
 *      callbacks, no fee on transfer, no rebasing. `nonReentrant` closes the callback case, without
 *      it, a token that reenters `swap` during the input pull runs the inner swap against STALE
 *      reserves while the outer call still applies its pre-computed `amountOut`, and the constant
 *      product FALLS (1,000/1,000 reserves, two 100-unit buys: k goes 1,000,000 -> 984,000). A
 *      fee-on-transfer or rebasing token is NOT covered by the guard and would silently desynchronise
 *      the internal reserves from the real balances; do not pair one here.
 */
contract GapCompliantDex is ReentrancyGuard {
    /// @notice Selector the DEX's filter is configured against for swaps.
    bytes4 public constant SWAP_SELECTOR = bytes4(keccak256("gapSwap()"));
    /// @notice Selector for adding or removing liquidity, gated separately from swapping.
    bytes4 public constant LIQUIDITY_SELECTOR = bytes4(keccak256("gapLiquidity()"));

    address public immutable security;
    address public immutable cash;
    /// @notice The DEX's OWN filter, over the DEX's own ORDB. Not the token's.
    TransactionFilterV2 public immutable transactionFilter;

    uint256 public securityReserve;
    uint256 public cashReserve;
    uint256 public totalShares;
    /// @notice Non-transferable by construction: there is no transfer function.
    mapping(address => uint256) public shares;

    /// @notice 30 bps, the conventional constant-product fee, retained in the reserves for LPs.
    uint256 private constant FEE_NUMERATOR = 997;
    uint256 private constant FEE_DENOMINATOR = 1000;
    uint256 private constant MIN_LIQUIDITY = 1000;

    event LiquidityAdded(address indexed provider, uint256 securityIn, uint256 cashIn, uint256 sharesOut);
    event LiquidityRemoved(address indexed provider, uint256 sharesIn, uint256 securityOut, uint256 cashOut);
    event Swapped(address indexed trader, bool securityIn, uint256 amountIn, uint256 amountOut);

    error DexZeroAddress();
    error DexNotEligible(address account);
    error DexInsufficientAmount();
    error DexInsufficientLiquidity();
    error DexSlippage(uint256 amountOut, uint256 minAmountOut);
    error DexTransferFailed();

    constructor(address security_, address cash_, address transactionFilter_) {
        if (security_ == address(0) || cash_ == address(0) || transactionFilter_ == address(0)) {
            revert DexZeroAddress();
        }
        security = security_;
        cash = cash_;
        transactionFilter = TransactionFilterV2(transactionFilter_);
    }

    // ---------- gating ----------

    /**
     * @dev The DEX's filter is asked about the caller for this selector. `check` is default-DENY on
     *      an unconfigured selector, so a DEX whose filter was never configured trades with nobody.
     */
    function _requireEligible(bytes4 selector, address account) private view {
        if (!transactionFilter.check(selector, account, address(0))) revert DexNotEligible(account);
    }

    function maySwap(address account) external view returns (bool) {
        return transactionFilter.check(SWAP_SELECTOR, account, address(0));
    }

    function mayProvideLiquidity(address account) external view returns (bool) {
        return transactionFilter.check(LIQUIDITY_SELECTOR, account, address(0));
    }

    // ---------- liquidity ----------

    function addLiquidity(uint256 securityIn, uint256 cashIn) external nonReentrant returns (uint256 sharesOut) {
        _requireEligible(LIQUIDITY_SELECTOR, msg.sender);
        if (securityIn == 0 || cashIn == 0) revert DexInsufficientAmount();

        if (totalShares == 0) {
            sharesOut = _sqrt(securityIn * cashIn);
            if (sharesOut <= MIN_LIQUIDITY) revert DexInsufficientLiquidity();
        } else {
            uint256 bySecurity = (securityIn * totalShares) / securityReserve;
            uint256 byCash = (cashIn * totalShares) / cashReserve;
            sharesOut = bySecurity < byCash ? bySecurity : byCash;
            if (sharesOut == 0) revert DexInsufficientLiquidity();
        }

        // Both pulls run the tokens' own gates, with this contract as recipient, which is where the
        // pool's Contract Session is what admits it.
        _pull(security, msg.sender, securityIn);
        _pull(cash, msg.sender, cashIn);
        securityReserve += securityIn;
        cashReserve += cashIn;
        totalShares += sharesOut;
        shares[msg.sender] += sharesOut;
        emit LiquidityAdded(msg.sender, securityIn, cashIn, sharesOut);
    }

    /**
     * @notice Withdraw a position. Still gated: a provider whose session has lapsed or whose
     *         pseudonym has been flagged cannot pull the security back out. That is deliberate and
     *         it is a real consequence: it is the same frozen-holder problem `RegulatedVenueV2`
     *         answers with `operatorTransfer`, and this reference venue has no such escape hatch.
     */
    function removeLiquidity(uint256 sharesIn) external nonReentrant returns (uint256 securityOut, uint256 cashOut) {
        _requireEligible(LIQUIDITY_SELECTOR, msg.sender);
        if (sharesIn == 0 || sharesIn > shares[msg.sender]) revert DexInsufficientAmount();

        securityOut = (securityReserve * sharesIn) / totalShares;
        cashOut = (cashReserve * sharesIn) / totalShares;
        if (securityOut == 0 || cashOut == 0) revert DexInsufficientLiquidity();

        shares[msg.sender] -= sharesIn;
        totalShares -= sharesIn;
        securityReserve -= securityOut;
        cashReserve -= cashOut;
        _push(security, msg.sender, securityOut);
        _push(cash, msg.sender, cashOut);
        emit LiquidityRemoved(msg.sender, sharesIn, securityOut, cashOut);
    }

    // ---------- swap ----------

    /**
     * @param securityIn true to sell the security for cash, false to buy it.
     * @dev Output always settles to `msg.sender`; there is no recipient argument to abuse.
     */
    function swap(bool securityIn, uint256 amountIn, uint256 minAmountOut)
        external
        nonReentrant
        returns (uint256 amountOut)
    {
        _requireEligible(SWAP_SELECTOR, msg.sender);
        if (amountIn == 0) revert DexInsufficientAmount();
        if (securityReserve == 0 || cashReserve == 0) revert DexInsufficientLiquidity();

        (uint256 reserveIn, uint256 reserveOut) =
            securityIn ? (securityReserve, cashReserve) : (cashReserve, securityReserve);
        uint256 amountInWithFee = amountIn * FEE_NUMERATOR;
        amountOut = (amountInWithFee * reserveOut) / (reserveIn * FEE_DENOMINATOR + amountInWithFee);
        if (amountOut == 0) revert DexInsufficientLiquidity();
        if (amountOut < minAmountOut) revert DexSlippage(amountOut, minAmountOut);

        if (securityIn) {
            _pull(security, msg.sender, amountIn);
            securityReserve += amountIn;
            cashReserve -= amountOut;
            _push(cash, msg.sender, amountOut);
        } else {
            _pull(cash, msg.sender, amountIn);
            cashReserve += amountIn;
            securityReserve -= amountOut;
            // Settles the gated security: the token's own gate runs with the pool as sender and the
            // trader as recipient, so both legs are checked independently of this contract.
            _push(security, msg.sender, amountOut);
        }
        emit Swapped(msg.sender, securityIn, amountIn, amountOut);
    }

    function quote(bool securityIn, uint256 amountIn) external view returns (uint256) {
        if (amountIn == 0 || securityReserve == 0 || cashReserve == 0) return 0;
        (uint256 reserveIn, uint256 reserveOut) =
            securityIn ? (securityReserve, cashReserve) : (cashReserve, securityReserve);
        uint256 amountInWithFee = amountIn * FEE_NUMERATOR;
        return (amountInWithFee * reserveOut) / (reserveIn * FEE_DENOMINATOR + amountInWithFee);
    }

    // ---------- transfers ----------

    function _pull(address token, address from, uint256 amount) private {
        if (!IErc20Minimal(token).transferFrom(from, address(this), amount)) revert DexTransferFailed();
    }

    function _push(address token, address to, uint256 amount) private {
        if (!IErc20Minimal(token).transfer(to, amount)) revert DexTransferFailed();
    }

    function _sqrt(uint256 x) private pure returns (uint256 y) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }
}
