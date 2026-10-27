// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "./GapDexFixture.sol";
import {GapCompliantDex} from "../../src/applications/dex/GapCompliantDex.sol";
import {SessionManager} from "../../src/v2/SessionManager.sol";
import {TransactionFilterV2} from "../../src/v2/TransactionFilterV2.sol";

/**
 * A cash leg that reenters `swap` during the input pull. Armed only after seeding, so the pool can be
 * funded normally first.
 *
 * The arithmetic this probes is real: `swap` computes `amountOut` from reserves, THEN pulls, THEN
 * updates, so an inner call on stale reserves plus an outer call applying a pre-computed amount takes
 * k from 1,000,000 down to 984,000 on 1,000/1,000 reserves with two 100-unit buys. See the comment at
 * the assertion for which mechanism actually prevents it, and which does not.
 */
contract ReenteringCash {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    GapCompliantDex public dex;
    bool public armed;
    bool private inside;

    function point(GapCompliantDex d) external { dex = d; }
    function arm() external { armed = true; }
    function mint(address to, uint256 v) external { balanceOf[to] += v; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v; balanceOf[to] += v; return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v; balanceOf[f] -= v; balanceOf[to] += v;
        if (armed && !inside) {
            inside = true;
            dex.swap(false, 100 ether, 0); // reenter while the outer call's reserves are stale
            inside = false;
        }
        return true;
    }
}

contract GapDexReentrancyTest is GapDexFixture {
    GapCompliantDex internal victim;
    ReenteringCash internal evilCash;

    function test_AReenteringCashTokenCannotDrainThePool() public {
        evilCash = new ReenteringCash();
        TransactionFilterV2 victimTf = new TransactionFilterV2(address(this), address(sm));
        victim = new GapCompliantDex(address(security), address(evilCash), address(victimTf));
        evilCash.point(victim);

        // Gate the victim pool exactly as the real one is gated.
        victimTf.setGatedContract(address(security));
        bytes32[] memory need = new bytes32[](1); need[0] = policyId;
        victimTf.setUserConfig(victim.SWAP_SELECTOR(), need);
        victimTf.setUserConfig(victim.LIQUIDITY_SELECTOR(), need);

        // Let the victim hold the security, the same way _classifyDex does for the real pool.
        uint256 idx = clsStore.addClassification(
            address(victim), address(cta), secRegime, DEX_CLASS, ccId, keccak256("victim"), address(this), "", true
        );
        sm.registerContractSession(address(victim), idx);
        address[] memory ctas = new address[](1); ctas[0] = address(cta);
        SessionManager.ContractRequirement[] memory reqs = new SessionManager.ContractRequirement[](1);
        reqs[0] = SessionManager.ContractRequirement(secRegime, DEX_CLASS, ctas, 30 days, true, true);
        tokenTf.setContractConfig(security.transfer.selector, reqs);
        tokenTf.setContractConfig(security.transferFrom.selector, reqs);

        evilCash.mint(alice, 1_000_000 ether);
        vm.startPrank(alice);
        security.approve(address(victim), type(uint256).max);
        evilCash.approve(address(victim), type(uint256).max);
        victim.addLiquidity(1000 ether, 1000 ether); // seeded while disarmed
        vm.stopPrank();

        uint256 kBefore = victim.securityReserve() * victim.cashReserve();
        evilCash.arm();

        /**
         * TWO INDEPENDENT MECHANISMS STOP THIS, and it is worth knowing which is load-bearing.
         *
         * `nonReentrant` is what fires here: the inner call hits the guard and reverts with
         * ReentrancyGuardReentrantCall (0x3ee5aeb5).
         *
         * But the COMPLIANCE GATE blocks it anyway. Verified by removing the guard and re-running:
         * the inner call then reverts with DexNotEligible(0x96d3…), selector 0x2f6d3ae5, because the
         * reentrant caller is the TOKEN CONTRACT, and a token holds no session. Every entry point here
         * gates on `msg.sender`, so a contract that reenters is refused for the same reason any
         * unsessioned party is.
         *
         * So the guard is defence in depth, not the fix for a live hole. Recorded rather than implied,
         * because "we added a reentrancy guard" reads like there was an exploitable drain, and there
         * was not, the arithmetic was reachable (k would fall 1,000,000 -> 984,000) but the call path
         * was not.
         */
        vm.prank(alice);
        vm.expectRevert();
        victim.swap(false, 100 ether, 0);

        // Whichever mechanism fires, the property that matters is the same: the whole transaction
        // reverts, so the constant product cannot move.
        assertEq(victim.securityReserve() * victim.cashReserve(), kBefore, "k must not move");
    }
}
