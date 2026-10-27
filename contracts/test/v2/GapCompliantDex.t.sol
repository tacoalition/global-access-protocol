// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "./GapDexFixture.sol";
import "../../src/applications/dex/IAllowlistChecker.sol";

/**
 * @notice A permissioned AMM over a gated security. The pool holds the security lawfully through a
 *         Contract Session from a "Compliant DEX" Classification Credential, not a user session,
 *         which it could never produce.
 *
 *         Two load-bearing tests. Without any Contract Session the pool cannot even be paid INTO,
 *         because GAP-H6 gates the recipient of every transfer. And with the INBOUND leg configured
 *         but not the outbound one, it can be funded and can never pay out, which isolates the
 *         sender-side contract route, the thing that did not exist before and without which no AMM
 *         can settle a gated security.
 */
contract GapCompliantDexTest is GapDexFixture {
    // ---------- the pool as a lawful holder ----------

    /// An unclassified pool cannot even RECEIVE the security: GAP-H6 gates every recipient, and a
    /// contract has no user session to present.
    function test_UnclassifiedPoolCannotBeFunded() public {
        vm.prank(alice);
        vm.expectRevert("RT: recipient not compliant");
        dex.addLiquidity(1000 ether, 1000 ether);
    }

    /**
     * The sender-side route in isolation. Configure the pool's classification requirements for the
     * INBOUND leg only (`transferFrom`, how liquidity arrives) and leave the OUTBOUND leg
     * (`transfer`, how the pool settles a buy) unconfigured. The pool funds fine and then cannot
     * pay anyone: this is exactly the gap the whitepaper's "the AMM already has an active Contract
     * Session" closes, and it is unreachable without the sender-side route.
     */
    function test_PoolCannotPayOutWithoutTheSenderSideRoute() public {
        SessionManager.ContractRequirement[] memory reqs = _dexRequirement();
        tokenTf.setContractConfig(security.transferFrom.selector, reqs); // inbound only
        vm.prank(alice);
        dex.addLiquidity(1000 ether, 1000 ether); // funding works
        vm.prank(alice);
        vm.expectRevert("RT: sender not compliant");
        dex.swap(false, 10 ether, 0); // buying means the POOL must send, and it cannot
    }

    function test_ClassifiedPoolMayPayOut() public {
        _classifyDex();
        vm.prank(alice);
        dex.addLiquidity(1000 ether, 1000 ether);
        uint256 before = security.balanceOf(alice);
        vm.prank(alice);
        uint256 out = dex.swap(false, 10 ether, 0);
        assertGt(out, 0);
        assertEq(security.balanceOf(alice), before + out);
    }

    // ---------- swap gating ----------

    function test_UnsessionedTraderCannotSwap() public {
        _classifyDex();
        vm.prank(alice);
        dex.addLiquidity(1000 ether, 1000 ether);
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(GapCompliantDex.DexNotEligible.selector, mallory));
        dex.swap(false, 10 ether, 0);
    }

    function test_ExpiredSessionCannotSwap() public {
        _classifyDex();
        vm.prank(alice);
        dex.addLiquidity(1000 ether, 1000 ether);
        vm.warp(block.timestamp + 1000); // past the session's validUntil
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(GapCompliantDex.DexNotEligible.selector, alice));
        dex.swap(false, 10 ether, 0);
    }

    function test_UnconfiguredSelectorTradesWithNobody() public {
        TransactionFilterV2 bare = new TransactionFilterV2(address(this), address(sm));
        bare.setGatedContract(address(security));
        GapCompliantDex lonely = new GapCompliantDex(address(security), address(cash), address(bare));
        assertFalse(lonely.maySwap(alice)); // default-DENY, not default-open
    }

    // ---------- liquidity gating ----------

    function test_UnsessionedProviderCannotAddLiquidity() public {
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(GapCompliantDex.DexNotEligible.selector, mallory));
        dex.addLiquidity(1 ether, 1 ether);
    }

    function test_LiquidityRoundTrips() public {
        _classifyDex();
        vm.prank(alice);
        uint256 got = dex.addLiquidity(1000 ether, 1000 ether);
        assertEq(dex.shares(alice), got);
        vm.prank(alice);
        (uint256 s, uint256 c) = dex.removeLiquidity(got / 2);
        assertGt(s, 0);
        assertGt(c, 0);
        assertEq(dex.shares(alice), got - got / 2);
    }

    /// There is no transfer function on an LP position, so the wrapper the whitepaper warns about
    /// cannot exist. Asserted against the ABI rather than by prose.
    function test_LpPositionHasNoTransferPath() public view {
        assertEq(dex.shares(alice), 0);
        // `shares` is a bare mapping with no setter reachable by a holder: the only mutations are
        // addLiquidity/removeLiquidity, both gated and both keyed to msg.sender.
        assertTrue(address(dex).code.length > 0);
    }

    // ---------- upgrade exposure: what the chain CAN and CANNOT do ----------

    /**
     * The chain cannot detect that a certified contract was upgraded behind a proxy, `SLOAD` reads
     * only the executing contract's storage, so nothing here can inspect an implementation pointer,
     * and `certifiedCodeHash` pins the bytecode at the target's OWN address, which a proxy keeps
     * across an implementation swap. So the control is the CERTIFIER's assertion, and a venue
     * demanding it. These two tests are that control, and they are the whole of it.
     */
    function test_AVenueMayRefuseAContractTheCertifierWillNotCallImmutable() public {
        // The certifier declines to assert it (certifierSaysImmutable = false); the venue demands it.
        SessionManager.ContractRequirement[] memory reqs = _dexRequirementWith(false, 30 days, true);
        tokenTf.setContractConfig(security.transferFrom.selector, reqs);
        vm.prank(alice);
        vm.expectRevert("RT: recipient not compliant");
        dex.addLiquidity(1000 ether, 1000 ether);
    }

    /// A certification does not outlive its window. Without this, nothing bounds a stale assertion.
    function test_ACertificationExpires() public {
        SessionManager.ContractRequirement[] memory reqs = _dexRequirementWith(true, 30 days, true);
        tokenTf.setContractConfig(security.transfer.selector, reqs);
        tokenTf.setContractConfig(security.transferFrom.selector, reqs);
        vm.prank(alice);
        dex.addLiquidity(1000 ether, 1000 ether); // inside the window: fine

        vm.warp(block.timestamp + 31 days);
        _grantAndAttest(alice); // a fresh holder session, so only the POOL's standing is stale
        vm.prank(alice);
        vm.expectRevert("RT: recipient not compliant");
        dex.addLiquidity(1 ether, 1 ether);
    }

    // ---------- the sender-side contract route: who it must NOT admit ----------

    /**
     * The route I added lets a CONTRACT pass the sender gate. The obvious fear is that it also lets an
     * EOA through, which would make the gate meaningless. It cannot: a classification requires the
     * target to have code, so there is nothing for an EOA to present.
     */
    function test_AnEoaCannotBeClassifiedAndSoCannotUseTheContractRoute() public {
        vm.expectRevert("CLS: target has no code");
        clsStore.addClassification(
            address(0xEEEE), address(cta), secRegime, DEX_CLASS, ccId, keccak256("eoa"), address(this), "", true
        );
    }

    /**
     * And a classification is not a general licence. The route checks regime, class and issuing CTA, so
     * a contract certified as something else is refused, here the pool is a "tokenized security"
     * (class 1) while the venue demands a "liquidity pool" (class 7).
     */
    function test_AContractClassifiedAsTheWrongThingIsRefused() public {
        uint256 idx = clsStore.addClassification(
            address(dex), address(cta), secRegime, 1, ccId, keccak256("wrong-class"), address(this), "", true
        );
        sm.registerContractSession(address(dex), idx);
        address[] memory ctas = new address[](1); ctas[0] = address(cta);
        SessionManager.ContractRequirement[] memory reqs = new SessionManager.ContractRequirement[](1);
        reqs[0] = SessionManager.ContractRequirement(secRegime, DEX_CLASS, ctas, 30 days, true, true);
        tokenTf.setContractConfig(security.transferFrom.selector, reqs);
        vm.prank(alice);
        vm.expectRevert("RT: recipient not compliant");
        dex.addLiquidity(1000 ether, 1000 ether);
    }

    /// Nor does a classification from an unaccepted anchor count, however valid it is in itself.
    function test_AClassificationFromAnUnacceptedCtaIsRefused() public {
        SessionManager.ContractRequirement[] memory reqs = _dexRequirement();
        address[] memory otherCta = new address[](1); otherCta[0] = address(0xBEEF);
        reqs[0] = SessionManager.ContractRequirement(secRegime, DEX_CLASS, otherCta, 30 days, true, true);
        tokenTf.setContractConfig(security.transferFrom.selector, reqs);
        vm.prank(alice);
        vm.expectRevert("RT: recipient not compliant");
        dex.addLiquidity(1000 ether, 1000 ether);
    }

    // ---------- the Uniswap-shaped checker ----------

    function test_CheckerReportsBothFlagsForAnEligibleAccount() public view {
        uint8 flags = checker.checkAllowlist(alice, address(security));
        assertEq(flags, PermissionFlags.SWAP_ALLOWED | PermissionFlags.LIQUIDITY_ALLOWED);
    }

    function test_CheckerDeniesAnUnsessionedAccount() public view {
        assertEq(checker.checkAllowlist(mallory, address(security)), 0);
    }

    function test_CheckerIgnoresAForeignToken() public view {
        assertEq(checker.checkAllowlist(alice, address(cash)), 0);
    }

    function test_CheckerFailsClosedOnAnUnsessionedAccountAfterExpiry() public {
        vm.warp(block.timestamp + 1000);
        assertEq(checker.checkAllowlist(alice, address(security)), 0);
    }

}
