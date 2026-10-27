// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Script.sol";
import "../../src/v2/RegimeRegistry.sol";
import "../../src/v2/DIDRegistryV2.sol";
import "../../src/v2/DIDSuccessionRegistry.sol";
import "../../src/v2/IdentityAnchor.sol";
import "../../src/v2/ClassificationAnchor.sol";
import "../../src/v2/ClassificationContract.sol";
import "../../src/v2/OnchainRiskDatabase.sol";
import "../../src/v2/UserPolicyRegistry.sol";
import "../../src/v2/SessionManager.sol";
import "../../src/v2/SessionVerifier.sol";
import "../../src/v2/TransactionFilterV2.sol";
import "../../src/v2/RegulatedTokenV2.sol";
import "../../src/v2/RegulatedVenueV2.sol";
import "../../src/v2/libraries/GapLib.sol";

/**
 * @notice Stands up the entire GAP v2 topology + demo scenario STRUCTURE on a local chain.
 *         Everything that is public config lives here; DID + credential issuance (which touch the
 *         private salt) are done offchain by the CLI bootstrap. The DEPLOYER plays every system
 *         role (ITA/CTA admin, IK/CC control key, TM, policy owner, TF admin) for a legible demo;
 *         the USER is a separate account. Writes deployments/{chainId}-v2.json.
 *
 *         Circuit-matched depths: DID 16, credential 16, ORDB 14 (SessionVerifier is for the
 *         MVP-local circuit, see circuits/src/v2/session.circom).
 */
contract DeployV2 is Script {
    uint256 constant DID_DEPTH = 16;
    uint256 constant CRED_DEPTH = 16;
    uint256 constant ORDB_DEPTH = 14;

    // THE DEMO MONITOR'S REAL BabyJubJub PUBLIC KEY, mirroring packages/gap-cli/src/monitor-key.ts.
    // This used to be the point (1, 2), not on the curve, so nothing could ECDH to it, so the
    // session envelope was shipped in CLEARTEXT and two wallets of one holder were publicly
    // linkable. The scalar behind this key is published alongside it and protects nothing; what it
    // buys is that the demo runs the production cipher instead of a stand-in.
    uint256 constant DEMO_MONITOR_PK_X =
        16748179299083121587732023489771520327604751973068439960861183512353334892500;
    uint256 constant DEMO_MONITOR_PK_Y =
        19635820508302344050006821993285090849409310344111641696431076536461503592449;

    struct Dep {
        address regimes; address did; address succession; address clsStore; address verifier; address policyReg;
        address sm; address ita; address cta; address tf; address token; address ordb; address poseidon;
        address venue; address venueOrdb;
        bytes32 ikId; bytes32 ccId; bytes32 policyId; bytes32 receivingPolicyId;
        bytes32 idRegime; bytes32 invRegime; bytes32 secRegime; bytes32 kybRegime; bytes32 monitorKeyId;
        // venue zone policy pairs (general + reg-d are satisfiable by the demo user's credentials)
        bytes32 genTransferPolicy; bytes32 genReceivingPolicy;
        bytes32 regdTransferPolicy; bytes32 regdReceivingPolicy;
    }

    function run() external {
        // THIS STACK IS FORGEABLE BY DESIGN: the committed verifier comes from a setup closed on a
        // published beacon, the monitor's private key is in the repository, and the deployer holds
        // every role. On any chain but a local Anvil that is a live system anyone can break.
        require(block.chainid == 31337, "Deploy: local Anvil (chain 31337) only, see SECURITY.md");
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address user = vm.envOr("USER_ADDRESS", address(0));
        address poseidon = _loadPoseidon();
        require(poseidon != address(0), "Deploy: no Poseidon2 deployment found, run `make up`");

        vm.startBroadcast(pk);
        Dep memory d = _deployAll(deployer, poseidon);
        _wirePolicyAndToken(d, deployer);
        _wireVenue(d, deployer);
        if (user != address(0)) RegulatedTokenV2(d.token).mint(user, 1_000_000 ether);
        vm.stopBroadcast();

        _write(chainIdStr(), _json(d, user));
        console.log("GAP v2 deployed. SessionManager:", d.sm);
        console.log("token:", d.token, "ordb:", d.ordb);
    }

    function _deployAll(address deployer, address poseidon) internal returns (Dep memory d) {
        d.poseidon = poseidon;
        d.idRegime = GapLib.regimeHash("standard-identity", 1, 0, 0);
        d.invRegime = GapLib.regimeHash("investor-status", 1, 0, 0);
        d.secRegime = GapLib.regimeHash("tokenized-securities", 1, 0, 0);

        RegimeRegistry regimes = new RegimeRegistry(0, address(0));
        regimes.proposeRegime("standard-identity", 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, "Standard Verified Identity", "ipfs://id", 4);
        regimes.proposeRegime("investor-status", 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, "Investor Status", "ipfs://inv", 4);
        regimes.proposeRegime("tokenized-securities", 1, 0, 0, RegimeRegistry.RegimeType.CLASSIFICATION, "Tokenized Securities", "ipfs://sec", 0);
        regimes.proposeRegime("entity-kyb", 1, 0, 0, RegimeRegistry.RegimeType.IDENTITY, "Entity (KYB)", "ipfs://kyb", 4);
        d.regimes = address(regimes);

        d.did = address(new DIDRegistryV2(poseidon, DID_DEPTH, 0, address(0)));
        // S6: the deployer plays the IK role here as it does everywhere else in this script, so it
        // is both the owner that grants writers and the first authorized succession writer. A real
        // deployment separates them: the IK key commits, an operator key grants.
        d.succession = address(new DIDSuccessionRegistry(deployer, deployer));
        d.clsStore = address(new ClassificationContract());
        d.verifier = address(new SessionVerifier());
        d.policyReg = address(new UserPolicyRegistry(poseidon, deployer));
        // The deployer is the TM in this stack: it curates which predicates a venue may carry and
        // authorises itself to register them. See docs/POLICY_AUTHORSHIP.md.
        UserPolicyRegistry(d.policyReg).setAuthor(deployer, true);
        d.sm = address(new SessionManager(d.policyReg, d.did, d.clsStore, d.verifier));

        IdentityAnchor ita = new IdentityAnchor(deployer, poseidon, CRED_DEPTH, address(regimes));
        ita.adoptRegime(d.idRegime);
        ita.adoptRegime(d.invRegime);
        bytes32[] memory ikRegimes = new bytes32[](2);
        ikRegimes[0] = d.idRegime; ikRegimes[1] = d.invRegime;
        address[] memory ikKeys = new address[](1); ikKeys[0] = deployer;
        d.ikId = ita.registerIK("acme-kyc", ikKeys, address(0), hex"01", ikRegimes, "ipfs://ik");
        d.ita = address(ita);

        ClassificationAnchor cta = new ClassificationAnchor(deployer, "ipfs://cta", address(regimes));
        cta.adoptRegime(d.secRegime);
        bytes32[] memory ccRegimes = new bytes32[](1); ccRegimes[0] = d.secRegime;
        address[] memory ccKeys = new address[](1); ccKeys[0] = deployer;
        d.ccId = cta.registerCC("audit-co", ccKeys, address(0), ccRegimes, "ipfs://cc");
        d.cta = address(cta);
    }

    function _wirePolicyAndToken(Dep memory d, address deployer) internal {
        TransactionFilterV2 tf = new TransactionFilterV2(deployer, d.sm);
        RegulatedTokenV2 token = new RegulatedTokenV2("Demo Fund Token", "dFUND", address(tf), deployer);
        d.tf = address(tf); d.token = address(token);

        d.monitorKeyId = GapLib.toField(keccak256("gap-demo-monitor-key"));
        d.ordb = address(new OnchainRiskDatabase(
            deployer, deployer, deployer, d.token, d.poseidon, ORDB_DEPTH, DEMO_MONITOR_PK_X, DEMO_MONITOR_PK_Y, d.monitorKeyId
        ));

        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(d.idRegime, d.ita);
        roots[1] = UserPolicyRegistry.IdentityRootSource(d.invRegime, d.ita);
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 0, UserPolicyRegistry.ClauseOp.EQ, 840);
        clauses[1] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);
        clauses[2] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[3] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[4] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[5] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        UserPolicyRegistry(d.policyReg).approvePredicate(clauses, "us-resident-not-sanctioned");
        d.policyId = UserPolicyRegistry(d.policyReg).registerPolicy("fund-transfer-policy", roots, d.ordb, clauses, 3600);
        // GAP-H6: the receiving policy, same eligibility DNF, its own (deliberately short, 24h)
        // session cap: receiving sessions are non-revocable, so a flagged recipient keeps
        // receiving only until this expiry.
        d.receivingPolicyId = UserPolicyRegistry(d.policyReg).registerPolicy("fund-receiving-policy", roots, d.ordb, clauses, 86400);

        tf.setGatedContract(d.token); // bind the TF (and thus sessions) to this token (audit)
        bytes32[] memory need = new bytes32[](1); need[0] = d.policyId;
        bytes32[] memory recv = new bytes32[](1); recv[0] = d.receivingPolicyId;
        tf.setUserConfig(token.transfer.selector, need);
        tf.setUserConfig(token.transferFrom.selector, need);
        tf.setRecipientConfig(token.transfer.selector, true, recv);      // GAP-H6: gate `to`
        tf.setRecipientConfig(token.transferFrom.selector, true, recv);

        uint256 clsIdx = ClassificationContract(d.clsStore).addClassification(
            d.token, d.cta, d.secRegime, 1, d.ccId, keccak256("audit-report"), deployer, "",
            true // RegulatedTokenV2 has no upgrade path
        );
        SessionManager(d.sm).registerContractSession(d.token, clsIdx);
    }

    /// @dev D1/D7: the venue + its ORDB + three zones from the catalog in
    ///      ZONES_AND_VENUE_DESIGN.md (full stack, not in this repository), each a (transfer, receiving) policy pair, and
    ///      one demo asset per zone. Purely additive: the legacy single-token path is untouched.
    function _wireVenue(Dep memory d, address deployer) internal {
        d.kybRegime = GapLib.regimeHash("entity-kyb", 1, 0, 0);
        IdentityAnchor(d.ita).adoptRegime(d.kybRegime);
        bytes32[] memory addKyb = new bytes32[](1); addKyb[0] = d.kybRegime;
        IdentityAnchor(d.ita).updateIKRegimes(d.ikId, addKyb, new bytes32[](0));

        RegulatedVenueV2 venue = new RegulatedVenueV2(deployer, d.sm);
        d.venue = address(venue);
        d.venueOrdb = address(new OnchainRiskDatabase(
            deployer, deployer, deployer, d.venue, d.poseidon, ORDB_DEPTH, DEMO_MONITOR_PK_X, DEMO_MONITOR_PK_Y,
            GapLib.toField(keccak256("gap-demo-venue-monitor-key"))
        ));
        venue.initOrdb(d.venueOrdb);

        // clause templates per the zone catalog (attrs: [0]=citizenship [1]=sanctioned, slot-1
        // regime at [2..3]). NOTE (audit): the entity zone does NOT require US citizenship, 
        // non-US KYB'd entities are eligible; only sanctioned==0 + kybVerified==1 apply.
        d.genTransferPolicy = _zonePolicy(d, "general-transfer", d.invRegime, true, false, 3600);
        d.genReceivingPolicy = _zonePolicy(d, "general-receiving", d.invRegime, true, false, 86400);
        venue.registerZone(keccak256("general"), d.genTransferPolicy, d.genReceivingPolicy);
        d.regdTransferPolicy = _zonePolicy(d, "reg-d-transfer", d.invRegime, true, true, 3600);
        d.regdReceivingPolicy = _zonePolicy(d, "reg-d-receiving", d.invRegime, true, true, 86400);
        venue.registerZone(keccak256("reg-d"), d.regdTransferPolicy, d.regdReceivingPolicy);
        venue.registerZone(keccak256("entity"),
            _zonePolicy(d, "entity-transfer", d.kybRegime, false, true, 3600),
            _zonePolicy(d, "entity-receiving", d.kybRegime, false, true, 86400));

        venue.registerAsset(keccak256("asset:dFUND-G"), "dFUND-G", keccak256("general"));
        venue.registerAsset(keccak256("asset:PRIV-D"), "PRIV-D", keccak256("reg-d"));
        venue.registerAsset(keccak256("asset:ENT-B"), "ENT-B", keccak256("entity"));
    }

    /// @dev One zone policy from the catalog template: always `sanctioned == 0`; optional
    ///      `citizenship == 840` (US-person zones); optional slot-1 gate (attrs[2]==1:
    ///      accredited for investor-status, kybVerified for entity-kyb).
    function _zonePolicy(
        Dep memory d, string memory name, bytes32 slot1Regime, bool requireUs, bool gateSlot1, uint64 validity
    ) internal returns (bytes32) {
        UserPolicyRegistry.IdentityRootSource[2] memory roots;
        roots[0] = UserPolicyRegistry.IdentityRootSource(d.idRegime, d.ita);
        roots[1] = UserPolicyRegistry.IdentityRootSource(slot1Regime, d.ita);
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);
        clauses[1] = requireUs
            ? UserPolicyRegistry.PolicyClause(true, 0, 0, UserPolicyRegistry.ClauseOp.EQ, 840)
            : UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[2] = gateSlot1
            ? UserPolicyRegistry.PolicyClause(true, 0, 4, UserPolicyRegistry.ClauseOp.EQ, 1) // accredited
            : UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[3] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[4] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[5] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        // Seeding the zone templates is what turns the reviewed-clause-set convention in
        // packages/gap-cli/src/state.ts into enforcement, with no behavioural change.
        UserPolicyRegistry(d.policyReg).approvePredicate(clauses, name);
        return UserPolicyRegistry(d.policyReg).registerPolicy(name, roots, d.venueOrdb, clauses, validity);
    }

    // ----- helpers -----

    function _loadPoseidon() internal view returns (address) {
        string memory f = string.concat("deployments/", chainIdStr(), "-poseidon.json");
        try vm.readFile(f) returns (string memory json) {
            return abi.decode(vm.parseJson(json, ".poseidon2"), (address));
        } catch { return address(0); }
    }

    function chainIdStr() internal view returns (string memory) {
        return vm.toString(block.chainid);
    }

    function _json(Dep memory d, address user) internal view returns (string memory) {
        string memory a = string.concat(
            "{\n",
            '  "regimeRegistry": "', vm.toString(d.regimes), '",\n',
            '  "didRegistry": "', vm.toString(d.did), '",\n',
            '  "didSuccessionRegistry": "', vm.toString(d.succession), '",\n',
            '  "classificationContract": "', vm.toString(d.clsStore), '",\n',
            '  "sessionVerifier": "', vm.toString(d.verifier), '",\n',
            '  "userPolicyRegistry": "', vm.toString(d.policyReg), '",\n',
            '  "sessionManager": "', vm.toString(d.sm), '",\n',
            '  "identityAnchor": "', vm.toString(d.ita), '",\n',
            '  "classificationAnchor": "', vm.toString(d.cta), '",\n',
            '  "transactionFilter": "', vm.toString(d.tf), '",\n'
        );
        string memory b = string.concat(a,
            '  "regulatedToken": "', vm.toString(d.token), '",\n',
            '  "ordb": "', vm.toString(d.ordb), '",\n',
            '  "poseidon2": "', vm.toString(d.poseidon), '",\n',
            '  "ikId": "', vm.toString(d.ikId), '",\n',
            '  "ccId": "', vm.toString(d.ccId), '",\n',
            '  "policyId": "', vm.toString(d.policyId), '",\n'
        );
        string memory c = string.concat(b,
            '  "receivingPolicyId": "', vm.toString(d.receivingPolicyId), '",\n',
            '  "idRegime": "', vm.toString(d.idRegime), '",\n',
            '  "invRegime": "', vm.toString(d.invRegime), '",\n',
            '  "secRegime": "', vm.toString(d.secRegime), '",\n',
            '  "monitorKeyId": "', vm.toString(d.monitorKeyId), '",\n'
        );
        string memory e = string.concat(c,
            '  "venue": "', vm.toString(d.venue), '",\n',
            '  "venueOrdb": "', vm.toString(d.venueOrdb), '",\n',
            '  "venueMonitorKeyId": "', vm.toString(GapLib.toField(keccak256("gap-demo-venue-monitor-key"))), '",\n',
            '  "kybRegime": "', vm.toString(d.kybRegime), '",\n'
        );
        return string.concat(e,
            '  "genTransferPolicy": "', vm.toString(d.genTransferPolicy), '",\n',
            '  "genReceivingPolicy": "', vm.toString(d.genReceivingPolicy), '",\n',
            '  "regdTransferPolicy": "', vm.toString(d.regdTransferPolicy), '",\n',
            '  "regdReceivingPolicy": "', vm.toString(d.regdReceivingPolicy), '",\n',
            '  "assetFUNDG": "', vm.toString(keccak256("asset:dFUND-G")), '",\n',
            '  "assetPRIVD": "', vm.toString(keccak256("asset:PRIV-D")), '",\n',
            '  "user": "', vm.toString(user), '"\n}'
        );
    }

    function _write(string memory chainId, string memory json) internal {
        vm.writeFile(string.concat("deployments/", chainId, "-v2.json"), json);
    }
}
