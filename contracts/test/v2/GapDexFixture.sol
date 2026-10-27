// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "../../src/v2/RegimeRegistry.sol";
import "forge-std/Test.sol";
import "../../src/v2/UserPolicyRegistry.sol";
import "../../src/v2/SessionManager.sol";
import "../../src/v2/DIDRegistryV2.sol";
import "../../src/v2/IdentityAnchor.sol";
import "../../src/v2/ClassificationAnchor.sol";
import "../../src/v2/ClassificationContract.sol";
import "../../src/v2/TransactionFilterV2.sol";
import "../../src/v2/RegulatedTokenV2.sol";
import "../../src/v2/OnchainRiskDatabase.sol";
import "../../src/v2/libraries/GapLib.sol";
import "../../src/applications/dex/GapCompliantDex.sol";
import "../../src/applications/dex/GapAllowlistChecker.sol";
import "../../src/applications/dex/IAllowlistChecker.sol";

contract DexMockVerifier {
    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[19] calldata)
        external pure returns (bool)
    { return true; }
}

/// Plain, ungated cash leg. A security trades against something; that something is not the subject.
contract CashToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 v) external { balanceOf[to] += v; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v; balanceOf[to] += v; return true;
    }
    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v; balanceOf[f] -= v; balanceOf[to] += v; return true;
    }
}

/**
 * @notice The full permissioned-AMM topology, wired as the GAP whitepaper §7 describes: a gated
 *         security with its own filter, a DEX with its OWN filter over its own ORDB, and a
 *         Classification Anchor able to issue the pool a "Compliant DEX" credential.
 * @dev Not a suite: a fixture, like SharedFundScopeFixture. `_classifyDex` and `_dexRequirement`
 *      are separate so a test can configure the inbound leg without the outbound one.
 */
abstract contract GapDexFixture is Test {
    UserPolicyRegistry internal policyReg;
    SessionManager internal sm;
    DIDRegistryV2 internal didReg;
    IdentityAnchor internal ita;
    ClassificationAnchor internal cta;
    ClassificationContract internal clsStore;
    TransactionFilterV2 internal tokenTf;
    TransactionFilterV2 internal dexTf;
    RegulatedTokenV2 internal security;
    CashToken internal cash;
    OnchainRiskDatabase internal ordb;
    GapCompliantDex internal dex;
    GapAllowlistChecker internal checker;

    address internal poseidon;
    bytes32 internal idRegime;
    bytes32 internal invRegime;
    bytes32 internal secRegime;
    bytes32 internal ccId;
    bytes32 internal policyId;
    bytes32 internal constant MONITOR_KEY_ID = bytes32(uint256(7));
    uint256 internal constant DEX_CLASS = 7; // "Liquidity Pool" in the phase-6 classification vocabulary

    address internal constant TM = address(0x7A);
    address internal alice = address(0xA11CE); // eligible LP + trader
    address internal mallory = address(0xBAD);  // never onboarded

    /// The shared regime registry this suite's anchors adopt from (Oct 2026 review, §5.3).
    address internal _regimes;

    function setUp() public {
        poseidon = _deployPoseidon();
        string[3] memory _ids;
        _ids[0] = "standard-identity";
        _ids[1] = "base-fund-eligibility";
        _ids[2] = "sec-contract-classification";
        _regimes = _regimeRegistryWith(_ids);
        idRegime = GapLib.regimeHash("standard-identity", 1, 0, 0);
        invRegime = GapLib.regimeHash("base-fund-eligibility", 1, 0, 0);
        secRegime = GapLib.regimeHash("sec-contract-classification", 1, 0, 0);

        didReg = new DIDRegistryV2(poseidon, 10, 0, address(0));
        ita = new IdentityAnchor(address(this), poseidon, 10, _regimes);
        ita.adoptRegime(idRegime);
        ita.adoptRegime(invRegime);
        clsStore = new ClassificationContract();
        policyReg = new UserPolicyRegistry(poseidon, address(this));
        policyReg.setAuthor(address(this), true);
        sm = new SessionManager(address(policyReg), address(didReg), address(clsStore), address(new DexMockVerifier()));

        cta = new ClassificationAnchor(address(this), "ipfs://cta", _regimes);
        cta.adoptRegime(secRegime);
        bytes32[] memory ccRegimes = new bytes32[](1); ccRegimes[0] = secRegime;
        address[] memory ccKeys = new address[](1); ccKeys[0] = address(this);
        ccId = cta.registerCC("audit-co", ccKeys, address(0), ccRegimes, "ipfs://cc");

        tokenTf = new TransactionFilterV2(address(this), address(sm));
        security = new RegulatedTokenV2("Demo Security", "SEC", address(tokenTf), address(this));
        cash = new CashToken();
        ordb = new OnchainRiskDatabase(
            address(this), TM, address(this), address(security), poseidon, 14, 1, 2, MONITOR_KEY_ID
        );

        policyId = _registerPolicy();
        tokenTf.setGatedContract(address(security));
        bytes32[] memory need = new bytes32[](1); need[0] = policyId;
        tokenTf.setUserConfig(security.transfer.selector, need);
        tokenTf.setUserConfig(security.transferFrom.selector, need);
        tokenTf.setRecipientConfig(security.transfer.selector, true, need);
        tokenTf.setRecipientConfig(security.transferFrom.selector, true, need);

        // The DEX's own filter, over the same sessions but its own selectors: the whitepaper's
        // "the DEX needs to have its own Transaction Filter".
        dexTf = new TransactionFilterV2(address(this), address(sm));
        dex = new GapCompliantDex(address(security), address(cash), address(dexTf));
        dexTf.setGatedContract(address(security));
        dexTf.setUserConfig(dex.SWAP_SELECTOR(), need);
        dexTf.setUserConfig(dex.LIQUIDITY_SELECTOR(), need);

        checker = new GapAllowlistChecker(
            address(security), address(security), address(sm), policyId, policyId
        );

        _grantAndAttest(alice);
        security.mint(alice, 1_000_000 ether);
        cash.mint(alice, 1_000_000 ether);
        cash.mint(mallory, 1_000 ether);
        vm.startPrank(alice);
        security.approve(address(dex), type(uint256).max);
        cash.approve(address(dex), type(uint256).max);
        vm.stopPrank();
    }

    // ---------- helpers ----------

    /// Gives the pool its "Compliant DEX" Classification Credential and indexes it as a Contract
    /// Session. Grants nothing by itself, validity is re-read live at every check.
    function _dexRequirement() internal returns (SessionManager.ContractRequirement[] memory reqs) {
        return _dexRequirementWith(true, 30 days, true);
    }

    /**
     * @param certifierSaysImmutable what the CERTIFIER asserts about the target's upgrade path
     * @param maxAge how long the venue trusts a certification before it must be renewed (0 = forever)
     * @param venueDemandsImmutable whether the venue requires that assertion
     */
    function _dexRequirementWith(bool certifierSaysImmutable, uint256 maxAge, bool venueDemandsImmutable)
        internal
        returns (SessionManager.ContractRequirement[] memory reqs)
    {
        uint256 idx = clsStore.addClassification(
            address(dex), address(cta), secRegime, DEX_CLASS, ccId, keccak256("dex-audit"), address(this), "",
            certifierSaysImmutable
        );
        sm.registerContractSession(address(dex), idx);
        address[] memory ctas = new address[](1); ctas[0] = address(cta);
        reqs = new SessionManager.ContractRequirement[](1);
        reqs[0] = SessionManager.ContractRequirement(secRegime, DEX_CLASS, ctas, maxAge, true, venueDemandsImmutable);
    }

    function _classifyDex() internal {
        SessionManager.ContractRequirement[] memory reqs = _dexRequirement();
        // The pool passes BOTH legs of the token's gate through this one configuration: the sender
        // route (new) when it pays out, the recipient route when it is paid into.
        tokenTf.setContractConfig(security.transfer.selector, reqs);
        tokenTf.setContractConfig(security.transferFrom.selector, reqs);
    }

    function _registerPolicy() internal returns (bytes32) {
        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(idRegime, address(ita));
        roots[1] = UserPolicyRegistry.IdentityRootSource(invRegime, address(ita));
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);
        for (uint256 i = 1; i < 6; i++) {
            clauses[i] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        }
        policyReg.approvePredicate(clauses, "not-sanctioned");
        return policyReg.registerPolicy("dex-holder", roots, address(ordb), clauses, 3600);
    }

    function _pub(address account, uint64 validUntil) internal view returns (uint256[19] memory pub) {
        (,,, bytes32 clausesHash,) = policyReg.getPolicyVersion(policyId, 1);
        pub[0] = uint256(uint160(account));
        pub[1] = block.chainid;
        pub[2] = uint256(uint160(address(sm)));
        pub[3] = uint256(clausesHash);
        pub[4] = uint256(validUntil);
        pub[5] = sm.sessionNonce(account);
        pub[6] = uint256(didReg.root());
        pub[7] = uint256(uint160(address(ita)));
        pub[8] = uint256(idRegime);
        pub[9] = uint256(ita.getAttributeRegimeRoot(idRegime));
        pub[10] = uint256(uint160(address(ita)));
        pub[11] = uint256(invRegime);
        pub[12] = uint256(ita.getAttributeRegimeRoot(invRegime));
        pub[13] = uint256(uint160(address(ordb)));
        pub[14] = uint256(ordb.root());
        pub[15] = uint256(uint160(address(security)));
        pub[16] = 111;
        pub[17] = 222;
        pub[18] = uint256(MONITOR_KEY_ID);
    }

    function _grantAndAttest(address account) internal {
        uint64 vu = uint64(block.timestamp + 100);
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        // pub MUST be built before the prank: `_pub` makes external view calls, and vm.prank
        // only survives until the next one.
        uint256[19] memory pub = _pub(account, vu);
        vm.prank(account);
        sm.grantSession(policyId, 1, vu, a, b, c, pub, "ct");
        bytes32 digest = sm.sessionDigestOf(account, policyId);
        vm.prank(TM);
        sm.attestSession(account, policyId, digest);
    }

    function _deployPoseidon() internal returns (address addr) {
        string memory raw = vm.readFile("bytecode/Poseidon2.bytecode");
        string[] memory parts = vm.split(raw, "\n");
        uint256 last = parts.length;
        while (last > 0 && bytes(parts[last - 1]).length == 0) last--;
        bytes memory code = vm.parseBytes(parts[last - 1]);
        assembly { addr := create(0, add(code, 0x20), mload(code)) }
        require(addr != address(0), "poseidon deploy failed");
    }

    /// @dev Regimes must exist in the shared registry before an anchor can adopt them (Oct 2026
    ///      review, §5.3). This seeds the ones this suite uses; the ids are the same strings the
    ///      `GapLib.regimeHash` calls derive from, so the hashes match by construction.
    function _regimeRegistryWith(string[3] memory ids) internal returns (address) {
        RegimeRegistry r = new RegimeRegistry(0, address(0));
        for (uint256 i = 0; i < ids.length; i++) {
            r.proposeRegime(ids[i], 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, ids[i], "", 4);
        }
        return address(r);
    }
}
