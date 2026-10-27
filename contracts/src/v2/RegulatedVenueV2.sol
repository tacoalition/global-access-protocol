// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./SessionManager.sol";
import "./UserPolicyRegistry.sol";
import "./OnchainRiskDatabase.sol";

/**
 * @title RegulatedVenueV2
 * @notice Venue-level gating (integration decision D1): ONE contract is the `gatedContract` for
 *         a whole universe of tokenized assets, organized into Regulated Zones (D7). A zone is a
 *         pair of UserPolicyRegistry policies (transfer + receiving); users hold up to two
 *         sessions per active zone, not one per asset. Assets are VENUE-NATIVE ledger entries
 *         (no external ERC-20 → no double-gating or direct-transfer bypass); withdrawal bridging
 *         is out of scope by design. Design + adversarial-review log:
 *         ZONES_AND_VENUE_DESIGN.md (full stack, not in this repository).
 * @dev The venue talks to the SessionManager DIRECTLY (TF selector configs cannot vary by
 *      asset). Sessions bind here because every zone policy names this venue's ORDB
 *      (`pub[13]`) whose `monitoredContract` is this venue (`pub[15]`), enforced at
 *      registration, not assumed. Pseudonyms are venue-wide (one flag blocks all zones, 
 *      deliberate, D1). Only external calls are SM/registry VIEWS (no reentrancy surface).
 */
contract RegulatedVenueV2 {
    struct Zone {
        bytes32 transferPolicyId;
        bytes32 receivingPolicyId;
        bool exists;
    }

    struct Asset {
        bytes32 zoneId;
        string symbol;
        bool exists;
    }

    address public operator;                 // the venue's TA/TM (D3: one role)
    SessionManager public immutable sessionManager;
    // Set ONCE via initOrdb: the ORDB constructor needs monitoredContract = this venue, so it
    // deploys after the venue (internal review: circular dependency). Zone registration is refused until
    // the ORDB is wired, fail-closed.
    address public ordb;

    mapping(bytes32 => Zone) private _zones;
    mapping(bytes32 => Asset) private _assets;
    mapping(bytes32 => mapping(address => uint256)) private _balances; // assetId → holder → units
    mapping(bytes32 => uint256) public totalIssued;                    // assetId → outstanding
    mapping(address => bool) public complianceEscrow;                  // operatorTransfer destinations

    event OrdbInitialized(address ordb);
    event ZoneRegistered(bytes32 indexed zoneId, bytes32 transferPolicyId, bytes32 receivingPolicyId);
    event AssetRegistered(bytes32 indexed assetId, string symbol, bytes32 indexed zoneId);
    event AssetRezoned(bytes32 indexed assetId, bytes32 indexed fromZone, bytes32 indexed toZone, string reason);
    event EscrowRegistered(address indexed escrow);
    event IssuanceRecorded(bytes32 indexed assetId, address indexed to, uint256 amount); // D12 issuance ledger
    event Retired(bytes32 indexed assetId, address indexed from, uint256 amount, string reason);
    event VenueTransfer(bytes32 indexed assetId, address indexed from, address indexed to, uint256 amount);
    event OperatorTransfer(bytes32 indexed assetId, address indexed from, address indexed to, uint256 amount, string reason);

    modifier onlyOperator() { require(msg.sender == operator, "Venue: not operator"); _; }

    constructor(address _operator, address _sessionManager) {
        require(_operator != address(0) && _sessionManager != address(0), "Venue: zero addr");
        operator = _operator;
        sessionManager = SessionManager(_sessionManager);
    }

    // ---------- wiring (operator) ----------

    /// @notice One-time ORDB wiring, coherence-checked: the ORDB must monitor THIS venue and its
    ///         TM must be the venue operator (TA = TM, D3): a mis-wired ORDB cannot be attached.
    function initOrdb(address ordb_) external onlyOperator {
        require(ordb == address(0), "Venue: ordb set");
        require(OnchainRiskDatabase(ordb_).monitoredContract() == address(this), "Venue: ordb not scoped here");
        require(OnchainRiskDatabase(ordb_).transactionMonitor() == operator, "Venue: ordb TM mismatch");
        ordb = ordb_;
        emit OrdbInitialized(ordb_);
    }

    /// @notice Register a zone (policy pair). Enforces role coherence (internal review finding): both
    ///         policies must be OWNED by the venue operator and must name THIS venue's ORDB, 
    ///         otherwise sessions would bind elsewhere or attestation authority would diverge.
    function registerZone(bytes32 zoneId, bytes32 transferPolicyId, bytes32 receivingPolicyId)
        external onlyOperator
    {
        require(ordb != address(0), "Venue: ordb unset");
        require(zoneId != bytes32(0) && !_zones[zoneId].exists, "Venue: bad/duplicate zone");
        _checkZonePolicy(transferPolicyId);
        _checkZonePolicy(receivingPolicyId);
        _zones[zoneId] = Zone(transferPolicyId, receivingPolicyId, true);
        emit ZoneRegistered(zoneId, transferPolicyId, receivingPolicyId);
    }

    function _checkZonePolicy(bytes32 policyId) private view {
        UserPolicyRegistry reg = sessionManager.policyRegistry();
        UserPolicyRegistry.PolicyMeta memory meta = reg.getPolicyMeta(policyId);
        require(meta.owner == operator, "Venue: policy not operator-owned");
        (, address requiredORDB,,,) = reg.getPolicyVersion(policyId, meta.latestVersion);
        require(requiredORDB == ordb, "Venue: policy ORDB mismatch");
    }

    function registerAsset(bytes32 assetId, string calldata symbol, bytes32 zoneId) external onlyOperator {
        require(assetId != bytes32(0) && !_assets[assetId].exists, "Venue: bad/duplicate asset");
        require(_zones[zoneId].exists, "Venue: unknown zone");
        _assets[assetId] = Asset(zoneId, symbol, true);
        emit AssetRegistered(assetId, symbol, zoneId);
    }

    /// @notice Re-zone an asset (event-logged; effective IMMEDIATELY for new transfers, 
    ///         sessions for the old zone simply stop matching: fail-closed).
    function rezoneAsset(bytes32 assetId, bytes32 newZoneId, string calldata reason) external onlyOperator {
        require(_assets[assetId].exists, "Venue: unknown asset");
        require(_zones[newZoneId].exists, "Venue: unknown zone");
        bytes32 old = _assets[assetId].zoneId;
        _assets[assetId].zoneId = newZoneId;
        emit AssetRezoned(assetId, old, newZoneId, reason);
    }

    function registerEscrow(address escrow) external onlyOperator {
        require(escrow != address(0), "Venue: zero addr");
        complianceEscrow[escrow] = true;
        emit EscrowRegistered(escrow);
    }

    // ---------- issuance (admin distribution exemption; the D12 issuance ledger) ----------

    function issue(bytes32 assetId, address to, uint256 amount) external onlyOperator {
        require(_assets[assetId].exists, "Venue: unknown asset");
        require(to != address(0) && amount > 0, "Venue: bad issue");
        _balances[assetId][to] += amount;
        totalIssued[assetId] += amount;
        emit IssuanceRecorded(assetId, to, amount);
    }

    /// @notice Forced burn (registrar power, redemptions, corporate actions). Reason-logged;
    ///         governance/multisig control of `operator` is the production safeguard.
    function retire(bytes32 assetId, address from, uint256 amount, string calldata reason) external onlyOperator {
        require(_assets[assetId].exists, "Venue: unknown asset");
        require(amount > 0, "Venue: bad retire");
        require(_balances[assetId][from] >= amount, "Venue: insufficient");
        _balances[assetId][from] -= amount;
        totalIssued[assetId] -= amount;
        emit Retired(assetId, from, amount, reason);
    }

    // ---------- the gated action ----------

    /// @notice Transfer within the venue: the sender needs the asset zone's TRANSFER session and
    ///         the recipient its RECEIVING session: both unexpired and TM-attested (GAP-H3/H6),
    ///         both proven FOR this venue.
    function transfer(bytes32 assetId, address to, uint256 amount) external {
        Zone storage zone = _zoneOf(assetId);
        require(to != address(0) && amount > 0, "Venue: bad transfer");
        require(_balances[assetId][msg.sender] >= amount, "Venue: insufficient");
        require(
            sessionManager.hasValidSession(msg.sender, zone.transferPolicyId, address(this)),
            "Venue: sender not compliant"
        );
        require(
            sessionManager.hasValidSession(to, zone.receivingPolicyId, address(this)),
            "Venue: recipient not compliant"
        );
        _balances[assetId][msg.sender] -= amount;
        _balances[assetId][to] += amount;
        emit VenueTransfer(assetId, msg.sender, to, amount);
    }

    /// @notice Operator forced transfer (court orders, escheatment, frozen-holder recovery: 
    ///         the only exit for a holder who can no longer open sessions). Destination-
    ///         constrained (internal review): `to` must hold the zone's receiving session OR be a
    ///         registered compliance escrow, forced moves cannot reach ineligible hands.
    function operatorTransfer(bytes32 assetId, address from, address to, uint256 amount, string calldata reason)
        external onlyOperator
    {
        Zone storage zone = _zoneOf(assetId);
        require(to != address(0) && amount > 0, "Venue: bad transfer");
        require(_balances[assetId][from] >= amount, "Venue: insufficient");
        require(
            complianceEscrow[to] || sessionManager.hasValidSession(to, zone.receivingPolicyId, address(this)),
            "Venue: destination not compliant"
        );
        _balances[assetId][from] -= amount;
        _balances[assetId][to] += amount;
        emit OperatorTransfer(assetId, from, to, amount, reason);
    }

    // ---------- views ----------

    function balanceOf(bytes32 assetId, address holder) external view returns (uint256) {
        return _balances[assetId][holder];
    }

    function getAsset(bytes32 assetId) external view returns (Asset memory) {
        return _assets[assetId];
    }

    function getZone(bytes32 zoneId) external view returns (Zone memory) {
        return _zones[zoneId];
    }

    /// @notice The UI's pre-flight ("checking recipient eligibility…"). Composes PUBLIC
    ///         hasValidSession views, intentional convenience over already-public data.
    function preflight(bytes32 assetId, address from, address to)
        external view returns (bool senderOk, bool recipientOk)
    {
        Zone storage zone = _zoneOf(assetId);
        senderOk = sessionManager.hasValidSession(from, zone.transferPolicyId, address(this));
        recipientOk = sessionManager.hasValidSession(to, zone.receivingPolicyId, address(this));
    }

    function _zoneOf(bytes32 assetId) private view returns (Zone storage zone) {
        Asset storage a = _assets[assetId];
        require(a.exists, "Venue: unknown asset");
        zone = _zones[a.zoneId];
        require(zone.exists, "Venue: unknown zone");
    }
}
