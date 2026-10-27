// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Script.sol";
import "../../src/v2/UserPolicyRegistry.sol";
import "../../src/v2/SessionManager.sol";
import "../../src/v2/TransactionFilterV2.sol";
import "../../src/v2/ClassificationContract.sol";
import "../../src/v2/OnchainRiskDatabase.sol";
import "../../src/applications/dex/GapCompliantDex.sol";
import "../../src/applications/dex/GapAllowlistChecker.sol";
import "../../src/applications/dex/DemoCashToken.sol";
import "../../src/v2/RegulatedTokenV2.sol";
import "../../src/v2/libraries/GapLib.sol";

/**
 * @notice Adds the permissioned-AMM layer on top of an existing v2 deployment. ADDITIVE and
 *         SEPARATE on purpose: `DeployV2.s.sol` is already at its stack-depth limit, the DEX is not
 *         required for the token story, and a reader should be able to see exactly which contracts
 *         the AMM introduces. Reads `deployments/<chainId>-v2.json`, writes `<chainId>-dex.json`.
 *
 * @dev THE DEX GETS ITS OWN SCOPE, not the token's, which is the whitepaper's model rather than a
 *      convenience: §7 has a swap needing a session PER CONTRACT, each with its own Transaction
 *      Filter, Transaction Monitor and Onchain Risk Database, because the AMM screens for market
 *      integrity (wash trading, sandwich attacks) while the token screens for AML/CFT. So a holder's
 *      token session does NOT admit them to the pool: they prove a second session scoped to the DEX,
 *      under a policy whose required ORDB is the DEX's own. That is what makes the pseudonyms
 *      per-contract and the flag surfaces independent.
 *
 *      Order is forced: the filter needs the Session Manager, the DEX needs the filter, the ORDB
 *      monitors the DEX so it needs the DEX's address, and the policy names the ORDB. Hence
 *      filter -> DEX -> ORDB -> policies -> configuration.
 */
contract DeployDexV2 is Script {
    uint256 internal constant ORDB_DEPTH = 14;

    // The pool's monitors get the same real key as the token's, see DeployV2. A placeholder here
    // would put the pool's sessions back in cleartext while the token's were sealed.
    uint256 constant DEMO_MONITOR_PK_X =
        16748179299083121587732023489771520327604751973068439960861183512353334892500;
    uint256 constant DEMO_MONITOR_PK_Y =
        19635820508302344050006821993285090849409310344111641696431076536461503592449;
    uint256 internal constant DEX_CLASS = 7; // "Liquidity Pool" in the phase-6 classification vocabulary

    struct V2 {
        address poseidon;
        address sm;
        address policyReg;
        address clsStore;
        address cta;
        address token;
        address tokenTf;
        bytes32 ccId;
        bytes32 secRegime;
        bytes32 idRegime;
        bytes32 invRegime;
        address ita;
    }

    struct Dex {
        address equity;
        address equityTf;
        bytes32 equityPolicy;
        address cash;
        address dexTf;
        address dex;
        address dexOrdb;
        address equityOrdb;
        address checker;
        bytes32 swapPolicy;
        bytes32 lpPolicy;
        bytes32 monitorKeyId;
    }

    function run() external {
        // THIS STACK IS FORGEABLE BY DESIGN: the committed verifier comes from a setup closed on a
        // published beacon, the monitor's private key is in the repository, and the deployer holds
        // every role. On any chain but a local Anvil that is a live system anyone can break.
        require(block.chainid == 31337, "Deploy: local Anvil (chain 31337) only, see SECURITY.md");
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        V2 memory v2 = _loadV2();

        vm.startBroadcast(pk);
        Dex memory d = _deploy(v2, deployer);
        _wire(v2, d, deployer);
        // Mint is an admin distribution exemption on RegulatedTokenV2, so the LP can be funded before
        // holding any session. Mirrors what DeployV2 does for the fund token.
        address user = vm.envOr("USER_ADDRESS", address(0));
        if (user != address(0)) RegulatedTokenV2(d.equity).mint(user, 1_000_000 ether);
        vm.stopBroadcast();

        _write(d, v2);
    }

    function _deploy(V2 memory v2, address deployer) internal returns (Dex memory d) {
        d.cash = address(new DemoCashToken(deployer));
        // The exemption's subject is tokenized NMS STOCK: a listed equity, not a treasury fund, so
        // the pool trades its own security rather than the fund token. That also makes per-security
        // scope real rather than architectural: this equity is a THIRD gating scope, so a holder's
        // fund sessions do not reach it and a flag here does not follow them to the fund.
        d.equityTf = address(new TransactionFilterV2(deployer, v2.sm));
        d.equity = address(new RegulatedTokenV2(
            "Demo Tokenized Equity (NMS)", "dNMS", d.equityTf, deployer
        ));
        // The DEX's OWN filter. Its gated contract is the DEX, so a session proven for the token
        // does not reach it.
        d.dexTf = address(new TransactionFilterV2(deployer, v2.sm));
        d.dex = address(new GapCompliantDex(d.equity, d.cash, d.dexTf));
        d.monitorKeyId = GapLib.toField(keccak256("gap-dex-monitor-key"));
        // The DEX's own Transaction Monitor surface: market-integrity flags, independent of the
        // token's AML/CFT ORDB, so flagging a trader here does not touch their holding session.
        d.dexOrdb = address(new OnchainRiskDatabase(
            deployer, deployer, deployer, d.dex, v2.poseidon, ORDB_DEPTH, DEMO_MONITOR_PK_X, DEMO_MONITOR_PK_Y, d.monitorKeyId
        ));
        // A session's SCOPE is derived from its ORDB: SessionManager requires
        // pub[15] == ordb.monitoredContract(). So a scope is exactly an ORDB, and the equity needs
        // its own, which is also what makes its flag surface independent of the pool's.
        d.equityOrdb = address(new OnchainRiskDatabase(
            deployer, deployer, deployer, d.equity, v2.poseidon, ORDB_DEPTH, DEMO_MONITOR_PK_X, DEMO_MONITOR_PK_Y, d.monitorKeyId
        ));
    }

    function _wire(V2 memory v2, Dex memory d, address deployer) internal {
        UserPolicyRegistry reg = UserPolicyRegistry(v2.policyReg);
        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(v2.idRegime, v2.ita);
        roots[1] = UserPolicyRegistry.IdentityRootSource(v2.invRegime, v2.ita);

        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);   // not sanctioned
        clauses[1] = UserPolicyRegistry.PolicyClause(true, 0, 0, UserPolicyRegistry.ClauseOp.EQ, 840); // resident US
        // THE THRESHOLD. Not an equality: the holder proves their accredited determination rests on
        // evidence of tier 3 OR BETTER without revealing which basis it was. This is the comparator
        // family (LT/LTE/GT/GTE) finally carrying a shipped clause: it was built, range-constrained
        // to 64 bits, and used by nothing.
        clauses[2] = UserPolicyRegistry.PolicyClause(true, 0, 6, UserPolicyRegistry.ClauseOp.GTE, 3);
        for (uint256 i = 3; i < 6; i++) {
            clauses[i] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        }
        reg.approvePredicate(clauses, "dex-us-resident-not-sanctioned-evidence-tier-3");
        d.swapPolicy = reg.registerPolicy("dex-swap-policy", roots, d.dexOrdb, clauses, 3600);

        // Liquidity is a SEPARATE policy even though the predicate matches today: an LP holds the
        // security's economics for as long as the position is open, so a venue may later demand more
        // of them than of a taker, and that should not require re-registering the swap policy.
        UserPolicyRegistry.PolicyClause[6] memory lpClauses = clauses;
        d.lpPolicy = reg.registerPolicy("dex-liquidity-policy", roots, d.dexOrdb, lpClauses, 3600);

        TransactionFilterV2 dexTf = TransactionFilterV2(d.dexTf);
        dexTf.setGatedContract(d.dex);
        bytes32[] memory swapNeed = new bytes32[](1); swapNeed[0] = d.swapPolicy;
        bytes32[] memory lpNeed = new bytes32[](1); lpNeed[0] = d.lpPolicy;
        dexTf.setUserConfig(GapCompliantDex(d.dex).SWAP_SELECTOR(), swapNeed);
        dexTf.setUserConfig(GapCompliantDex(d.dex).LIQUIDITY_SELECTOR(), lpNeed);

        // One policy serves the equity's sender AND recipient config, so a single holder session
        // covers both directions. A real venue would split them the way the fund lane does.
        d.equityPolicy = reg.registerPolicy("dex-equity-holder-policy", roots, d.equityOrdb, clauses, 86400);
        TransactionFilterV2 equityTf = TransactionFilterV2(d.equityTf);
        equityTf.setGatedContract(d.equity);
        bytes32[] memory hold = new bytes32[](1); hold[0] = d.equityPolicy;
        equityTf.setUserConfig(IERC20Selectors.transfer.selector, hold);
        equityTf.setUserConfig(IERC20Selectors.transferFrom.selector, hold);
        equityTf.setRecipientConfig(IERC20Selectors.transfer.selector, true, hold);
        equityTf.setRecipientConfig(IERC20Selectors.transferFrom.selector, true, hold);

        _admitPoolAsHolder(v2, d, deployer);

        d.checker = address(new GapAllowlistChecker(
            d.equity, d.dex, v2.sm, d.swapPolicy, d.lpPolicy
        ));
    }

    /**
     * @dev The pool holds the security, so it must be a lawful holder of it. It cannot hold a user
     *      session: the grant path needs a spending-set membership proof it has no DID or salt to
     *      make, so it gets a "Compliant DEX" Classification Credential and the token's filter is
     *      told to accept that class on BOTH legs. Without the outbound leg the pool can be funded
     *      and can never pay anyone.
     */
    function _admitPoolAsHolder(V2 memory v2, Dex memory d, address deployer) internal {
        uint256 idx = ClassificationContract(v2.clsStore).addClassification(
            d.dex, v2.cta, v2.secRegime, DEX_CLASS, v2.ccId, keccak256("dex-audit-report"), deployer, "",
            true // GapCompliantDex has no upgrade path: no proxy, no delegatecall, immutable config
        );
        SessionManager(v2.sm).registerContractSession(d.dex, idx);

        address[] memory ctas = new address[](1); ctas[0] = v2.cta;
        SessionManager.ContractRequirement[] memory reqs = new SessionManager.ContractRequirement[](1);
        // maxAge is 30 DAYS, not 0. A certification that never expires is the only thing standing
        // between a venue and a contract that was upgraded after being certified, and the chain
        // cannot detect that upgrade, so a bounded re-certification window IS the control.
        // requireImmutableCode demands the certifier actually asserted there is no upgrade path.
        reqs[0] = SessionManager.ContractRequirement(v2.secRegime, DEX_CLASS, ctas, 30 days, true, true);
        // The pool holds the EQUITY, so the equity's filter is the one that must accept it on both
        // legs. Without the outbound leg the pool can be funded and can never pay anyone.
        TransactionFilterV2 equityTf = TransactionFilterV2(d.equityTf);
        equityTf.setContractConfig(IERC20Selectors.transfer.selector, reqs);
        equityTf.setContractConfig(IERC20Selectors.transferFrom.selector, reqs);
    }

    // ----- deployment io -----

    function _loadV2() internal view returns (V2 memory v2) {
        string memory path = string.concat("deployments/", vm.toString(block.chainid), "-v2.json");
        string memory json = vm.readFile(path);
        v2.poseidon = vm.parseJsonAddress(json, ".poseidon2");
        v2.sm = vm.parseJsonAddress(json, ".sessionManager");
        v2.policyReg = vm.parseJsonAddress(json, ".userPolicyRegistry");
        v2.clsStore = vm.parseJsonAddress(json, ".classificationContract");
        v2.cta = vm.parseJsonAddress(json, ".classificationAnchor");
        v2.token = vm.parseJsonAddress(json, ".regulatedToken");
        v2.tokenTf = vm.parseJsonAddress(json, ".transactionFilter");
        v2.ita = vm.parseJsonAddress(json, ".identityAnchor");
        v2.ccId = vm.parseJsonBytes32(json, ".ccId");
        v2.secRegime = vm.parseJsonBytes32(json, ".secRegime");
        v2.idRegime = vm.parseJsonBytes32(json, ".idRegime");
        v2.invRegime = vm.parseJsonBytes32(json, ".invRegime");
    }

    function _write(Dex memory d, V2 memory v2) internal {
        string memory out = "dex";
        vm.serializeAddress(out, "cashToken", d.cash);
        vm.serializeAddress(out, "dexTransactionFilter", d.dexTf);
        vm.serializeAddress(out, "gapCompliantDex", d.dex);
        vm.serializeAddress(out, "dexOrdb", d.dexOrdb);
        vm.serializeAddress(out, "equityOrdb", d.equityOrdb);
        vm.serializeAddress(out, "gapAllowlistChecker", d.checker);
        vm.serializeAddress(out, "security", d.equity);
        vm.serializeAddress(out, "equityTransactionFilter", d.equityTf);
        vm.serializeBytes32(out, "dexEquityPolicy", d.equityPolicy);
        vm.serializeBytes32(out, "dexSwapPolicy", d.swapPolicy);
        vm.serializeBytes32(out, "dexLiquidityPolicy", d.lpPolicy);
        string memory json = vm.serializeBytes32(out, "dexMonitorKeyId", d.monitorKeyId);
        vm.writeJson(json, string.concat("deployments/", vm.toString(block.chainid), "-dex.json"));
    }
}

/// @dev Selector source for the gated token's ERC-20 entry points; `RegulatedTokenV2` overrides both.
interface IERC20Selectors {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}
