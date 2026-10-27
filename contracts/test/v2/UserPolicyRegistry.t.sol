// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../../src/v2/UserPolicyRegistry.sol";

/**
 * Curated authorship (docs/POLICY_AUTHORSHIP.md). The registry is the only place that can
 * stop a venue authoring a predicate narrow enough to identify one holder, because clauses are
 * public here and session grants are public on the Session Manager: "X holds a session under P"
 * discloses that X satisfies all of P. These tests are the floor, not the vocabulary.
 */
contract UserPolicyRegistryTest is Test {
    UserPolicyRegistry internal reg;
    address internal poseidon;
    address internal constant CURATOR = address(0xC0);
    address internal constant VENUE = address(0xBEEF);
    address internal constant ORDB = address(0xD8);
    address internal constant ITA = address(0x1A);
    bytes32 internal constant REGIME0 = keccak256("standard-identity");
    bytes32 internal constant REGIME1 = keccak256("base-fund-eligibility");

    function setUp() public {
        poseidon = _deployPoseidon();
        reg = new UserPolicyRegistry(poseidon, CURATOR);
        vm.prank(CURATOR);
        reg.setAuthor(VENUE, true);
    }

    // ---------- the floor ----------

    function test_UnapprovedPredicateCannotBeRegistered() public {
        vm.prank(VENUE);
        vm.expectRevert("Policy: predicate not approved");
        reg.registerPolicy("narrow", _roots(), ORDB, _narrowClauses(), 3600);
    }

    /// The register-clean-then-narrow-by-update path: both writes share `_storeVersion`.
    function test_ApprovedPolicyCannotBeUpdatedToAnUnapprovedPredicate() public {
        bytes32 id = _registerBroad();
        vm.prank(VENUE);
        vm.expectRevert("Policy: predicate not approved");
        reg.updatePolicy(id, _roots(), ORDB, _narrowClauses(), 3600);
    }

    function test_ApprovedPredicateRegisters() public {
        bytes32 id = _registerBroad();
        assertEq(reg.latestVersion(id), 1);
        (,,, bytes32 clausesHash,) = reg.getPolicyVersion(id, 1);
        assertTrue(reg.predicateApproved(clausesHash));
        assertEq(reg.predicateName(clausesHash), "not-sanctioned");
    }

    // ---------- authorship ----------

    function test_NonAuthorCannotRegister() public {
        vm.prank(CURATOR);
        reg.approvePredicate(_broadClauses(), "not-sanctioned");
        vm.prank(address(0xDEAD));
        vm.expectRevert("Policy: not author");
        reg.registerPolicy("sneaky", _roots(), ORDB, _broadClauses(), 3600);
    }

    function test_NonCuratorCannotApproveOrAuthorise() public {
        vm.prank(VENUE);
        vm.expectRevert("Policy: not curator");
        reg.approvePredicate(_narrowClauses(), "mine");
        vm.prank(VENUE);
        vm.expectRevert("Policy: not curator");
        reg.setAuthor(VENUE, true);
    }

    function test_AuthorshipIsRevocable() public {
        vm.prank(CURATOR);
        reg.approvePredicate(_broadClauses(), "not-sanctioned");
        vm.prank(CURATOR);
        reg.setAuthor(VENUE, false);
        vm.prank(VENUE);
        vm.expectRevert("Policy: not author");
        reg.registerPolicy("p", _roots(), ORDB, _broadClauses(), 3600);
    }

    // ---------- revocation blocks new versions, never a live one ----------

    function test_RevokedPredicateBlocksNewVersionsButKeepsTheLiveOne() public {
        bytes32 id = _registerBroad();
        (,,, bytes32 clausesHash,) = reg.getPolicyVersion(id, 1);

        vm.prank(CURATOR);
        reg.revokePredicate(clausesHash);
        assertFalse(reg.predicateApproved(clausesHash));

        // the live version is untouched, sessions proven against it must run to expiry
        (,,, bytes32 stillThere,) = reg.getPolicyVersion(id, 1);
        assertEq(stillThere, clausesHash);
        assertEq(reg.latestVersion(id), 1);

        // but it can no longer back a new version
        vm.prank(VENUE);
        vm.expectRevert("Policy: predicate not approved");
        reg.updatePolicy(id, _roots(), ORDB, _broadClauses(), 3600);
    }

    function test_RevokingAnUnapprovedPredicateReverts() public {
        vm.prank(CURATOR);
        vm.expectRevert("Policy: predicate not approved");
        reg.revokePredicate(keccak256("never-approved"));
    }

    // ---------- shape is still validated, at approval time too ----------

    function test_CuratorCannotApproveAnOutOfRangeAttrIndex() public {
        UserPolicyRegistry.PolicyClause[6] memory clauses;
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 8, UserPolicyRegistry.ClauseOp.EQ, 1);
        vm.prank(CURATOR);
        vm.expectRevert("Policy: attrIndex");
        reg.approvePredicate(clauses, "eight-is-out-of-range");
    }

    function test_CuratorshipTransfers() public {
        address next = address(0xC1);
        vm.prank(CURATOR);
        reg.transferCuratorship(next);
        assertEq(reg.curator(), next);
        vm.prank(CURATOR);
        vm.expectRevert("Policy: not curator");
        reg.setAuthor(VENUE, true);
    }

    // ---------- helpers ----------

    function _roots() internal pure returns (UserPolicyRegistry.IdentityRootSource[2] memory roots) {
        roots[0] = UserPolicyRegistry.IdentityRootSource(REGIME0, ITA);
        roots[1] = UserPolicyRegistry.IdentityRootSource(REGIME1, ITA);
    }

    /// A deliberately broad predicate: one clause, a large cohort.
    function _broadClauses() internal pure returns (UserPolicyRegistry.PolicyClause[6] memory clauses) {
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 1, UserPolicyRegistry.ClauseOp.EQ, 0);
        for (uint256 i = 1; i < 6; i++) {
            clauses[i] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        }
    }

    /**
     * The predicate the floor exists to refuse: residency AND citizenship AND accredited AND QP,
     * which under the V3 vocabulary is a near-singleton cohort. Nothing about its SHAPE is invalid
     *: every clause is well formed, which is the point. Only curation can stop it.
     */
    function _narrowClauses() internal pure returns (UserPolicyRegistry.PolicyClause[6] memory clauses) {
        clauses[0] = UserPolicyRegistry.PolicyClause(true, 0, 0, UserPolicyRegistry.ClauseOp.EQ, 840);
        clauses[1] = UserPolicyRegistry.PolicyClause(true, 0, 2, UserPolicyRegistry.ClauseOp.EQ, 442);
        clauses[2] = UserPolicyRegistry.PolicyClause(true, 0, 4, UserPolicyRegistry.ClauseOp.EQ, 1);
        clauses[3] = UserPolicyRegistry.PolicyClause(true, 0, 5, UserPolicyRegistry.ClauseOp.EQ, 1);
        clauses[4] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
        clauses[5] = UserPolicyRegistry.PolicyClause(false, 0, 0, UserPolicyRegistry.ClauseOp.NONE, 0);
    }

    function _registerBroad() internal returns (bytes32 id) {
        vm.prank(CURATOR);
        reg.approvePredicate(_broadClauses(), "not-sanctioned");
        vm.prank(VENUE);
        id = reg.registerPolicy("broad", _roots(), ORDB, _broadClauses(), 3600);
    }

    /// The shared idiom: the on-chain Poseidon2 is deployed from committed bytecode, not compiled.
    function _deployPoseidon() internal returns (address addr) {
        string memory raw = vm.readFile("bytecode/Poseidon2.bytecode");
        string[] memory parts = vm.split(raw, "\n");
        uint256 last = parts.length;
        while (last > 0 && bytes(parts[last - 1]).length == 0) last--;
        bytes memory code = vm.parseBytes(parts[last - 1]);
        assembly { addr := create(0, add(code, 0x20), mload(code)) }
        require(addr != address(0), "poseidon deploy failed");
    }

    // ---------- registry/circuit parity: refuse what the circuit cannot prove ----------

    /**
     * A curator could approve, and a venue register, a predicate no holder could ever satisfy: the
     * circuit range-checks clause values to 64 bits, so a larger operand makes it UNSATISFIABLE and
     * every session proof then failed at witness generation with nothing pointing at the cause.
     */
    function test_AClauseValueTheCircuitCannotRepresentIsRefused() public {
        UserPolicyRegistry.PolicyClause[6] memory clauses = _broadClauses();
        clauses[0].value = uint256(1) << 64;          // one past what Num2Bits(64) admits
        // Refused at APPROVAL, which is earlier and better than refusing at registration: the
        // curator never gets to bless something unprovable in the first place.
        vm.prank(CURATOR);
        vm.expectRevert("Policy: value exceeds the circuit's 64-bit range");
        reg.approvePredicate(clauses, "too-wide");
    }

    /// Likewise an enabled clause with no operator: `policy.circom` asserts `enabled * opIsNone === 0`.
    function test_AnEnabledClauseWithNoOperatorIsRefused() public {
        UserPolicyRegistry.PolicyClause[6] memory clauses = _broadClauses();
        clauses[1].enabled = true;
        clauses[1].op = UserPolicyRegistry.ClauseOp.NONE;
        vm.prank(CURATOR);
        vm.expectRevert("Policy: an enabled clause needs an operator");
        reg.approvePredicate(clauses, "no-op");
    }
}
