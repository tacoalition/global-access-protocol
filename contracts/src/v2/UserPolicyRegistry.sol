// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./libraries/GapLib.sol";
import "../interfaces/IPoseidon2.sol";

/**
 * @title UserPolicyRegistry
 * @notice User Policies per handoff/03 §8: mutable + versioned, self-describing root sources
 *         (per-regime accepted ITAs + required ORDB), fixed-size DNF predicate over attributes,
 *         and a session-lifetime cap.
 * @dev AUTHORSHIP IS CURATED, and it must be. Clauses are public here and session grants are
 *      public on the Session Manager, so "account X holds a session under policy P" discloses
 *      that X satisfies P's entire conjunction. The proof hides the attribute VALUES; it cannot
 *      hide that they satisfied a published predicate. With a wide vocabulary a venue can author
 *      a predicate narrow enough to match one person and then read the holder off SessionGranted.
 *      Cohort size cannot be computed on-chain: it depends on real-world population
 *      distributions, so this contract does not try. A curator approves reviewed clause sets and
 *      a policy may only carry one of them. See docs/POLICY_AUTHORSHIP.md.
 * @dev MVP shape (Spike-A build params): N_REGIMES = 2 (fixed), 1 required ORDB per policy
 *      (the policy is the TM's own per-contract config, so its ORDB is that contract's),
 *      MAX_CLAUSES = 6, MAX_GROUPS = 2, attributes indexed 0..7 (4 per regime).
 *      clausesHash = fold-left Poseidon2 over (meta, value) per clause, computed
 *      ON-CHAIN once per version; the circuit recomputes it from private clause witnesses and
 *      exposes it as a public input the Session Manager pins (no in-circuit keccak).
 */
contract UserPolicyRegistry {
    uint256 public constant N_REGIMES = 2;
    uint256 public constant MAX_CLAUSES = 6;

    enum ClauseOp { NONE, EQ, NEQ, LT, LTE, GT, GTE }

    struct PolicyClause {
        bool enabled;
        uint8 groupId;    // 0..1, clauses in a group AND; groups OR
        uint8 attrIndex;  // 0..7 (regime0 attrs at 0..3, regime1 attrs at 4..7)
        ClauseOp op;
        uint256 value;    // comparator operand (field element; comparators use 64-bit range)
    }

    struct IdentityRootSource {
        bytes32 regimeHash;  // the Attribute Regime the user must hold a credential for
        address ita;         // which ITA contract supplies THAT regime's root (per-regime pairing)
    }

    struct PolicyVersion {
        IdentityRootSource[N_REGIMES] identityRoots;
        address requiredORDB;
        PolicyClause[MAX_CLAUSES] clauses;
        bytes32 clausesHash;        // Poseidon2 fold: the circuit-bound predicate commitment
        uint64 maxSessionValidity;  // CAP on validUntil-now (seconds)
        uint256 createdAt;
    }

    struct PolicyMeta {
        bytes32 policyIdHash;
        string name;
        address owner;      // mutable-admin: the contract's TM under P0-6
        uint32 latestVersion;
        bool exists;
    }

    address public immutable poseidon;
    /// @notice Governance: approves the predicates a policy may carry, and who may author one.
    address public curator;
    mapping(bytes32 => PolicyMeta) private _meta;
    mapping(bytes32 => mapping(uint32 => PolicyVersion)) private _versions;
    /// @dev clausesHash => approved. The gate is the canonical predicate commitment already
    ///      computed below, so enforcement is one SLOAD and the granularity is exactly right:
    ///      a venue keeps free choice of identityRoots, requiredORDB and maxSessionValidity, and
    ///      loses only the ability to invent its own predicate.
    mapping(bytes32 => bool) private _approvedPredicate;
    /// @notice Human-readable name of an approved predicate, for UIs. Empty once revoked.
    mapping(bytes32 => string) public predicateName;
    /// @notice Who may call `registerPolicy`. `updatePolicy` stays owner-gated.
    mapping(address => bool) public isAuthor;

    event PolicyRegistered(bytes32 indexed policyId, address indexed owner, string name);
    event PolicyUpdated(bytes32 indexed policyId, uint32 version, bytes32 clausesHash);
    event PredicateApproved(bytes32 indexed predicateHash, string name, PolicyClause[MAX_CLAUSES] clauses);
    event PredicateRevoked(bytes32 indexed predicateHash);
    event AuthorSet(address indexed who, bool allowed);
    event CuratorTransferred(address indexed from, address indexed to);

    modifier onlyCurator() { require(msg.sender == curator, "Policy: not curator"); _; }

    constructor(address _poseidon, address _curator) {
        require(_curator != address(0), "Policy: curator");
        poseidon = _poseidon;
        curator = _curator;
    }

    // ---------- curation ----------

    /**
     * @notice Approve a reviewed clause set. Takes the CLAUSES, not a bare digest: a curator must
     *         never approve an opaque hash, and the event carries the predicate in the clear.
     * @dev Idempotent, re-approving an already-approved predicate simply refreshes its name.
     */
    function approvePredicate(PolicyClause[MAX_CLAUSES] calldata clauses, string calldata name)
        external onlyCurator returns (bytes32 predicateHash)
    {
        _validateClauses(clauses);
        predicateHash = _computeClausesHash(clauses);
        _approvedPredicate[predicateHash] = true;
        predicateName[predicateHash] = name;
        emit PredicateApproved(predicateHash, name, clauses);
    }

    /**
     * @notice Retire a predicate. Blocks NEW versions only; live sessions run to expiry, matching
     *         the `updatePolicy` rule. A session whose predicate was later retired is not a
     *         compliance failure, and tearing it down mid-flight would make revocation a
     *         denial-of-service lever against holders.
     */
    function revokePredicate(bytes32 predicateHash) external onlyCurator {
        require(_approvedPredicate[predicateHash], "Policy: predicate not approved");
        delete _approvedPredicate[predicateHash];
        delete predicateName[predicateHash];
        emit PredicateRevoked(predicateHash);
    }

    function setAuthor(address who, bool allowed) external onlyCurator {
        require(who != address(0), "Policy: author");
        isAuthor[who] = allowed;
        emit AuthorSet(who, allowed);
    }

    function transferCuratorship(address to) external onlyCurator {
        require(to != address(0), "Policy: curator");
        emit CuratorTransferred(curator, to);
        curator = to;
    }

    function predicateApproved(bytes32 predicateHash) external view returns (bool) {
        return _approvedPredicate[predicateHash];
    }

    /// @notice Create v1 of a policy. policyId = keccak(owner, name), STABLE, not content-addressed.
    function registerPolicy(
        string calldata name,
        IdentityRootSource[N_REGIMES] calldata identityRoots,
        address requiredORDB,
        PolicyClause[MAX_CLAUSES] calldata clauses,
        uint64 maxSessionValidity
    ) external returns (bytes32 policyId) {
        require(isAuthor[msg.sender], "Policy: not author");
        policyId = GapLib.policyId(msg.sender, name);
        require(!_meta[policyId].exists, "Policy: exists");
        _meta[policyId] = PolicyMeta(policyId, name, msg.sender, 1, true);
        _storeVersion(policyId, 1, identityRoots, requiredORDB, clauses, maxSessionValidity);
        emit PolicyRegistered(policyId, msg.sender, name);
    }

    /// @notice Mutable-admin update → new version. Existing sessions run to expiry (P1-8).
    function updatePolicy(
        bytes32 policyId,
        IdentityRootSource[N_REGIMES] calldata identityRoots,
        address requiredORDB,
        PolicyClause[MAX_CLAUSES] calldata clauses,
        uint64 maxSessionValidity
    ) external returns (uint32 version) {
        PolicyMeta storage m = _meta[policyId];
        require(m.exists, "Policy: not found");
        require(m.owner == msg.sender, "Policy: not owner");
        version = ++m.latestVersion;
        _storeVersion(policyId, version, identityRoots, requiredORDB, clauses, maxSessionValidity);
    }

    function _storeVersion(
        bytes32 policyId,
        uint32 version,
        IdentityRootSource[N_REGIMES] calldata identityRoots,
        address requiredORDB,
        PolicyClause[MAX_CLAUSES] calldata clauses,
        uint64 maxSessionValidity
    ) private {
        require(requiredORDB != address(0), "Policy: ordb");
        require(maxSessionValidity > 0, "Policy: validity");
        for (uint256 i = 0; i < N_REGIMES; i++) {
            require(identityRoots[i].ita != address(0), "Policy: ita");
            require(identityRoots[i].regimeHash != bytes32(0), "Policy: regime");
        }
        _validateClauses(clauses);
        PolicyVersion storage v = _versions[policyId][version];
        for (uint256 i = 0; i < N_REGIMES; i++) v.identityRoots[i] = identityRoots[i];
        v.requiredORDB = requiredORDB;
        for (uint256 i = 0; i < MAX_CLAUSES; i++) v.clauses[i] = clauses[i];
        v.clausesHash = _computeClausesHash(clauses);
        // BOTH registerPolicy and updatePolicy route through here, so register-clean-then-narrow
        // by update is covered by this one check.
        require(_approvedPredicate[v.clausesHash], "Policy: predicate not approved");
        v.maxSessionValidity = maxSessionValidity;
        v.createdAt = block.timestamp;
        emit PolicyUpdated(policyId, version, v.clausesHash);
    }

    /**
     * @dev THE CIRCUIT IS STRICTER, AND THIS NOW MATCHES IT. Two shapes used to pass here and fail
     *      in-circuit, which produced a curator-approved, successfully-registered policy under which
     *      every session proof failed at witness generation with nothing pointing at the cause:
     *
     *      - `value >= 2^64`. `policy.circom` range-checks clause values to 64 bits
     *        (`Num2Bits(64)`), so a larger operand makes the circuit UNSATISFIABLE. The comment there
     *        already claimed this was "contract-enforced too"; it was not, until now.
     *      - an ENABLED clause with `op == NONE`. `policy.circom` asserts
     *        `enabled * opIsNone.out === 0`.
     *
     *      Liveness rather than soundness, but it is a footgun aimed at the curator, who is the one
     *      role the design says cannot be automated.
     */
    function _validateClauses(PolicyClause[MAX_CLAUSES] calldata clauses) private pure {
        for (uint256 i = 0; i < MAX_CLAUSES; i++) {
            require(uint8(clauses[i].op) <= uint8(ClauseOp.GTE), "Policy: op");
            require(clauses[i].attrIndex < 8, "Policy: attrIndex");
            require(clauses[i].groupId < 2, "Policy: groupId");
            require(clauses[i].value < (1 << 64), "Policy: value exceeds the circuit's 64-bit range");
            require(
                !clauses[i].enabled || clauses[i].op != ClauseOp.NONE,
                "Policy: an enabled clause needs an operator"
            );
        }
    }

    /**
     * @notice Canonical predicate commitment: acc = 0; per clause: acc = H2(H2(acc, meta), value)
     *         with meta = enabled | groupId<<8 | attrIndex<<16 | op<<24. Matches the circuit fold.
     */
    function _computeClausesHash(PolicyClause[MAX_CLAUSES] calldata clauses) private view returns (bytes32) {
        IPoseidon2 h = IPoseidon2(poseidon);
        bytes32 acc = bytes32(0);
        for (uint256 i = 0; i < MAX_CLAUSES; i++) {
            uint256 meta = (clauses[i].enabled ? 1 : 0)
                | (uint256(clauses[i].groupId) << 8)
                | (uint256(clauses[i].attrIndex) << 16)
                | (uint256(uint8(clauses[i].op)) << 24);
            acc = h.poseidon([acc, bytes32(meta)]);
            acc = h.poseidon([acc, bytes32(clauses[i].value)]);
        }
        return acc;
    }

    // ---------- views ----------

    function getPolicyMeta(bytes32 policyId) external view returns (PolicyMeta memory) {
        require(_meta[policyId].exists, "Policy: not found");
        return _meta[policyId];
    }

    function getPolicyVersion(bytes32 policyId, uint32 version) external view returns (
        IdentityRootSource[N_REGIMES] memory identityRoots,
        address requiredORDB,
        PolicyClause[MAX_CLAUSES] memory clauses,
        bytes32 clausesHash,
        uint64 maxSessionValidity
    ) {
        require(_meta[policyId].exists && version >= 1 && version <= _meta[policyId].latestVersion, "Policy: bad version");
        PolicyVersion storage v = _versions[policyId][version];
        for (uint256 i = 0; i < N_REGIMES; i++) identityRoots[i] = v.identityRoots[i];
        for (uint256 i = 0; i < MAX_CLAUSES; i++) clauses[i] = v.clauses[i];
        return (identityRoots, v.requiredORDB, clauses, v.clausesHash, v.maxSessionValidity);
    }

    function latestVersion(bytes32 policyId) external view returns (uint32) {
        require(_meta[policyId].exists, "Policy: not found");
        return _meta[policyId].latestVersion;
    }

    /// @notice EVM-side DNF evaluation (parity harness vs the circuit gadget; offchain checks).
    function evaluate(bytes32 policyId, uint32 version, uint256[8] calldata attributes)
        external view returns (bool)
    {
        PolicyVersion storage v = _versions[policyId][version];
        require(v.createdAt != 0, "Policy: bad version");
        // A PARITY HARNESS MUST BE AT PARITY. The circuit range-checks attributes to 64 bits
        // (`Num2Bits(64)` in gap_session.circom), so a full-width comparison here would DISAGREE with
        // the circuit for any attribute at or above 2^64, and silently, since this is the function
        // callers reach for when they want to know what the circuit will decide.
        for (uint256 i = 0; i < 8; i++) {
            require(attributes[i] < (1 << 64), "Policy: attribute exceeds the circuit's 64-bit range");
        }
        bool anyGroup = false;
        for (uint8 g = 0; g < 2; g++) {
            bool groupPass = true;
            bool groupHasClause = false;
            for (uint256 i = 0; i < MAX_CLAUSES; i++) {
                PolicyClause storage c = v.clauses[i];
                if (!c.enabled || c.groupId != g) continue;
                groupHasClause = true;
                uint256 a = attributes[c.attrIndex];
                bool pass =
                    c.op == ClauseOp.EQ  ? a == c.value :
                    c.op == ClauseOp.NEQ ? a != c.value :
                    c.op == ClauseOp.LT  ? a <  c.value :
                    c.op == ClauseOp.LTE ? a <= c.value :
                    c.op == ClauseOp.GT  ? a >  c.value :
                    c.op == ClauseOp.GTE ? a >= c.value : false;
                if (!pass) { groupPass = false; break; }
            }
            if (groupHasClause && groupPass) anyGroup = true;
        }
        return anyGroup;
    }
}
