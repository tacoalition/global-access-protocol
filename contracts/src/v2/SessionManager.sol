// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "./UserPolicyRegistry.sol";
import "./DIDRegistryV2.sol";
import "./IdentityAnchor.sol";
import "./OnchainRiskDatabase.sol";
import "./ClassificationContract.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./libraries/RelayedGrantAuth.sol";

interface ISessionVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[19] calldata pubSignals
    ) external view returns (bool);
}

/**
 * @title SessionManager
 * @notice Singleton per handoff/03 §9: verifies the session proof against LIVE on-chain roots
 *         at grant time, then records a MINIMAL User Session, plus Contract Sessions (P1-14)
 *         so the TF checks one location for any argument.
 *
 * PUBLIC INPUT LAYOUT (19, must match circuits/src/v2/session.circom exactly):
 *  [0] account  [1] chainId  [2] sessionManager  [3] clausesHash  [4] validUntil  [5] accountNonce
 *  [6] didRoot
 *  [7] ita0  [8] regimeHash0  [9] credRoot0
 *  [10] ita1 [11] regimeHash1 [12] credRoot1
 *  [13] ordbId  [14] riskRoot  [15] gatedContract
 *  [16] pseudonymCommitment  [17] ikRefCommitment  [18] monitorKeyId
 */
contract SessionManager is ReentrancyGuard {
    struct UserSession {
        uint64 validUntil;          // primary validity mechanism (P1-8)
        bytes32 policyId;
        uint32 policyVersion;       // attested at grant; not retroactively invalidated
        address gatedContract;      // the contract the proof was scoped to (pub[15]): the TF must match
        address ordb;               // the risk DB the proof was scoped to (pub[13]): its TM attests/revokes
        bool attested;              // GAP-H3: unusable until the TM confirms the ciphertext reopens
        bytes encryptedPseudonym;   // abi.encode(pseudCommit, ikRefCommit, monitorKeyId, ciphertext)
    }

    uint256 public constant MAX_CONTRACT_SESSIONS = 16; // per (target, CTA): anti-griefing cap (internal review)

    /// @notice The scalar fields of a grant. Grouped into a struct because `grantSessionFor` cannot
    ///         pass eleven flat parameters through the EVM stack without `via_ir` (which the pinned
    ///         build settings do not enable). `deadline` is meaningful on the RELAYED path only, 
    ///         `grantSession` passes 0 and never reads it.


    UserPolicyRegistry public immutable policyRegistry;
    DIDRegistryV2 public immutable didRegistry;
    ClassificationContract public immutable classificationStore;
    ISessionVerifier public immutable verifier;

    mapping(address => mapping(bytes32 => UserSession)) private _sessions; // live (TF-visible) slot
    mapping(address => mapping(bytes32 => UserSession)) private _pending;  // staged renewal slot
    mapping(address => uint256) public sessionNonce; // per-account replay nullifier
    /// @dev target => issuing CTA => index. Keyed by CTA so a list can only be filled with entries
    ///      from that CTA: anyone can stand up an anchor and certify a target with it, and a single
    ///      list per target let sixteen such entries lock out every real certifier.
    mapping(address => mapping(address => ContractSession[])) private _contractSessions;

    struct ContractRequirement {
        bytes32 regimeHash;
        uint256 class;
        address[] acceptedCTAs;
        uint256 maxAge;             // 0 = no limit
        bool requireCodeMatch;
        /**
         * Demand the certifier's assertion that the target has no upgrade path. `requireCodeMatch`
         * alone does NOT cover this: it compares EXTCODEHASH at the target's own address, which a
         * proxy keeps unchanged across an implementation swap. A venue admitting a contract as a
         * lawful holder of a security should set this, and should set a finite `maxAge`.
         */
        bool requireImmutableCode;
    }

    struct ContractSession {
        uint256 credentialIdx;      // pointer into the Classification store, live re-validation source
        bool exists;
    }

    event SessionGranted(
        address indexed account,
        bytes32 indexed policyId,
        uint32 policyVersion,
        uint64 validUntil,
        bytes encryptedPseudonym
    );
    event SessionStaged(address indexed account, bytes32 indexed policyId, uint64 validUntil);
    event SessionPromoted(address indexed account, bytes32 indexed policyId, bytes32 sessionDigest);
    event SessionAttested(address indexed account, bytes32 indexed policyId, bytes32 sessionDigest);
    event SessionRevoked(address indexed account, bytes32 indexed policyId, address revoker);
    event ContractSessionRegistered(address indexed target, address indexed cta, uint256 credentialIdx);

    constructor(address _policyRegistry, address _didRegistry, address _classificationStore, address _verifier) {
        policyRegistry = UserPolicyRegistry(_policyRegistry);
        didRegistry = DIDRegistryV2(_didRegistry);
        classificationStore = ClassificationContract(_classificationStore);
        verifier = ISessionVerifier(_verifier);
    }

    // ---------- User Sessions ----------

    /// @notice Direct path: the account itself installs its session. `pub[0] == msg.sender` is the
    ///         only proof-of-possession of the account key in the stack (the circuit proves the
    ///         address is a MEMBER of the spending-key tree, not that the prover holds its key) and
    ///         is the documented mitigation for "Receiver Session Impersonation" (phase2 §Security).
    function grantSession(
        bytes32 policyId,
        uint32 policyVersion,
        uint64 validUntil,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[19] calldata pub,
        bytes calldata ciphertext
    ) external nonReentrant {
        RelayedGrantAuth.SessionGrant memory g = RelayedGrantAuth.SessionGrant(msg.sender, policyId, policyVersion, validUntil, 0);
        _checkBindings(g, pub);
        require(verifier.verifyProof(pA, pB, pC, pub), "SM: invalid proof");
        _install(g, pub, ciphertext);
    }

    /**
     * @notice Relayed path: a third party submits the transaction, but authorization still comes
     *         from `account`'s key via an EIP-712 signature: the msg.sender check is REPLACED, not
     *         removed, so "only the account owner can install a session at its slot" is preserved.
     * @dev EIP-1271 (contract accounts) is deliberately NOT supported. This signature is the stack's
     *      sole proof-of-possession of the account key; delegating it to arbitrary, mutable contract
     *      code would let any permissive/buggy `isValidSignature` silently downgrade the GAP-H6
     *      recipient gate, and it would add an untrusted external call to the grant path. (OZ's
     *      SignatureChecker is also ^0.8.24-only here.) Contract accounts use `grantSession`
     *      directly. `deadline` bounds how long a relayer may sit on an authorization, see
     *      `revokeSession`, which also bumps the nonce so revocation cannot be undone by a held one.
     */
    function grantSessionFor(
        RelayedGrantAuth.SessionGrant calldata grant,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[19] calldata pub,
        bytes calldata ciphertext,
        bytes calldata signature
    ) external nonReentrant {
        _authorizeRelayed(grant, pub, ciphertext, signature);
        RelayedGrantAuth.SessionGrant memory g = grant;
        _checkBindings(g, pub);
        require(verifier.verifyProof(pA, pB, pC, pub), "SM: invalid proof");
        _install(g, pub, ciphertext);
    }

    /// @notice EIP-712 domain separator, binds chainId and this contract address.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return RelayedGrantAuth.domainSeparator();
    }

    /// @notice The exact digest a relayed grant must be signed over (wallet/relayer helper).
    function relayedGrantDigest(
        RelayedGrantAuth.SessionGrant memory g,
        bytes32 pubDigest,
        bytes32 ciphertextDigest,
        uint256 nonce
    ) public view returns (bytes32) {
        return RelayedGrantAuth.digest(g, pubDigest, ciphertextDigest, nonce);
    }

    /// @dev Own stack frame: grantSessionFor already carries seven calldata parameters, so
    ///      reading the nonce inline there is stack-too-deep at 0.8.20 without via_ir.
    function _authorizeRelayed(
        RelayedGrantAuth.SessionGrant calldata grant,
        uint256[19] calldata pub,
        bytes calldata ciphertext,
        bytes calldata signature
    ) private view {
        RelayedGrantAuth.requireAuthorized(grant, pub, ciphertext, signature, sessionNonce[grant.account]);
    }

    /**
     * @dev Shared install step (both entry points reach it only after the same bindings + proof
     *      verification). NON-DESTRUCTIVE (staged renewal): if the account already holds a LIVE,
     *      ATTESTED session for this policy, the new one is written to the staging slot and the live
     *      one keeps serving the TF until the TM attests the stage, at which point the stage is
     *      promoted atomically. Overwriting unconditionally (the previous behaviour) meant any
     *      re-grant, including an early renewal, destroyed a working session and left the account
     *      dark until the TM re-attested: a self-inflicted DoS.
     *      The reviewed property is preserved for the session that is actually installed: a grant
     *      NEVER writes `attested = true`, in either slot. Staging was chosen over "refuse the
     *      re-grant unless forced" because refusal does not fix early renewal at all: the user
     *      would still have to let the session lapse (or force-destroy it) to rotate.
     */
    function _install(RelayedGrantAuth.SessionGrant memory g, uint256[19] calldata pub, bytes calldata ciphertext) private {
        sessionNonce[g.account] += 1;

        // The circuit binds pseudonymCommitment/ikRefCommitment/monitorKeyId (pub[16..18]);
        // the off-circuit ECIES ciphertext travels here so the contract's TM can decrypt and
        // reopen the commitments (Spike-A option-3). GAP-H3: the session is stored UNATTESTED, 
        // unusable until the ORDB's TM confirms offchain that the ciphertext decrypts to the
        // committed {pseudonym, blindingR, IK_ref} and calls attestSession.
        bytes memory encPseudonym = abi.encode(pub[16], pub[17], pub[18], ciphertext);
        UserSession storage live = _sessions[g.account][g.policyId];
        bool stage = live.attested && live.validUntil >= block.timestamp;
        UserSession storage slot = stage ? _pending[g.account][g.policyId] : live;

        slot.validUntil = g.validUntil;
        slot.policyId = g.policyId;
        slot.policyVersion = g.policyVersion;
        slot.gatedContract = address(uint160(pub[15])); // bind the session to the contract it was proven for
        slot.ordb = address(uint160(pub[13]));          // its TM is the attestor / revoker
        slot.attested = false;                          // a fresh ciphertext needs a fresh attestation
        slot.encryptedPseudonym = encPseudonym;
        // A stale stage must never outrank a newer direct install.
        if (!stage) delete _pending[g.account][g.policyId];

        if (stage) emit SessionStaged(g.account, g.policyId, g.validUntil);
        emit SessionGranted(g.account, g.policyId, g.policyVersion, g.validUntil, encPseudonym);
    }

    /// @dev All pre-install guards, run identically on both entry points.
    function _checkBindings(RelayedGrantAuth.SessionGrant memory g, uint256[19] calldata pub) private view {
        _checkAccountBindings(g.account, g.validUntil, pub);
        _checkPolicyBindings(g.policyId, g.policyVersion, g.validUntil, pub);
    }

    /// @notice GAP-H3 pre-attestation: the TM of the session's ORDB confirms it decrypted the
    ///         ciphertext and the plaintext reopens the proven commitments (pub[16]/pub[17]).
    ///         `sessionDigest` binds the attestation to the EXACT stored session: a user cannot
    ///         front-run the TM with a re-granted garbage-ciphertext session and inherit the
    ///         attestation (adversarial finding). If the digest names the STAGED session, that
    ///         session is promoted into the live slot atomically (see `_install`). Authority is read
    ///         from the TARGETED session's own ORDB, so a policy that re-pointed its ORDB can still
    ///         have its staged renewal attested by the new TM. The contract cannot
    ///         verify the decryption itself; the TM is incentive-aligned and already trusted for
    ///         flagging. TM liveness is the accepted route-(a) tradeoff, see
    ///         V2_PRODUCTION_HARDENING.md GAP-H3.
    function attestSession(address account, bytes32 policyId, bytes32 sessionDigest) external {
        UserSession storage staged = _pending[account][policyId];
        bool targetsStaged = staged.validUntil != 0 && sessionDigest == _digestOf(account, staged);
        UserSession storage target = targetsStaged ? staged : _sessions[account][policyId];

        require(target.validUntil != 0, "SM: no session");
        require(msg.sender == OnchainRiskDatabase(target.ordb).transactionMonitor(), "SM: not session TM");
        require(sessionDigest == _digestOf(account, target), "SM: session digest mismatch");

        if (targetsStaged) {
            // An expired stage must not be allowed to displace a live attested session.
            require(staged.validUntil >= block.timestamp, "SM: staged expired");
            _sessions[account][policyId] = staged;
            _sessions[account][policyId].attested = true;
            delete _pending[account][policyId];
            emit SessionPromoted(account, policyId, sessionDigest);
        } else {
            target.attested = true;
        }
        emit SessionAttested(account, policyId, sessionDigest);
    }

    /**
     * @notice Explicit revocation. Without it, session TTL IS the revocation latency, which is the
     *         only reason sessions must be short (and therefore proving frequent). Authority is the
     *         SAME as `attestSession`: the transaction monitor of the ORDB the session was proven
     *         against (pub[13], pinned to the policy's `requiredORDB` at grant). No new admin role.
     * @dev Idempotent and safe on a non-existent session: with nothing stored there is no ORDB to
     *      authenticate against, so the call is a silent no-op rather than a revert. Any staged
     *      renewal is cleared too, otherwise promoting it would instantly undo the revocation, 
     *      authority is taken from the LIVE session when one exists (a stage only ever exists behind
     *      a live one), and revocation is remove-only, so it can never escalate either TM's reach.
     *      `sessionNonce` is bumped so a relayer holding an unexpired `grantSessionFor` signature
     *      cannot re-install the session it just lost. Revocation removes THIS session; durable
     *      exclusion is an ORDB flag, which also changes `riskRoot` and invalidates every
     *      outstanding proof for that ORDB.
     */
    /**
     * @notice Close a flagged holder's session. The caller must PROVE the grounds.
     * @dev    WHY THE EXTRA ARGUMENTS. The GAP paper (p.19, §6.3) states as a design property that
     *         "there is no mechanism by which an Identity Keeper, Transaction Monitor, or outside
     *         observer can dynamically invalidate the User Session". This function is a deliberate
     *         departure from that, and an October 2026 review was right to flag it, but the version
     *         it flagged let the session's TM delete ANY session, for any reason or none, leaving no
     *         on-chain trace of why.
     *
     *         A precondition did exist; it just lived off-chain in the TM service, where it gates
     *         pseudonym RESOLUTION rather than this call. Off-chain is the right place for that
     *         check, resolving an unflagged pseudonym is the same computation as resolving a
     *         flagged one, so the service must refuse before it decrypts, but it left the contract
     *         itself unconditional.
     *
     *         Now the grounds are on-chain and checkable by anyone: the pseudonym must be flagged in
     *         the session's own ORDB, AND it must reopen the commitment this session was granted
     *         under. Both, or the call reverts. The second half is what stops a TM presenting some
     *         other pseudonym it happens to know is flagged as grounds against an unrelated account.
     *
     *         The TM learns `pseudonym` and `blindingR` when it decrypts to attest, so it already
     *         holds everything this signature asks for. Revealing the pseudonym costs nothing: the
     *         flag set is public by necessity (ON_CHAIN_DISCLOSURE.md).
     */
    function revokeSession(address account, bytes32 policyId, bytes32 pseudonym, bytes32 blindingR)
        external
    {
        UserSession storage live = _sessions[account][policyId];
        UserSession storage staged = _pending[account][policyId];
        bool hasLive = live.validUntil != 0;
        if (!hasLive && staged.validUntil == 0) return; // nothing to revoke: no-op, not a revert

        address authority = hasLive ? live.ordb : staged.ordb;
        require(msg.sender == OnchainRiskDatabase(authority).transactionMonitor(), "SM: not session TM");

        // The grounds, bound to THIS session. `encryptedPseudonym` is
        // abi.encode(pseudCommit, ikRefCommit, monitorKeyId, ciphertext).
        bytes memory enc = hasLive ? live.encryptedPseudonym : staged.encryptedPseudonym;
        (bytes32 pseudCommit,,,) = abi.decode(enc, (bytes32, bytes32, bytes32, bytes));
        require(
            OnchainRiskDatabase(authority).isFlaggedForCommitment(pseudonym, blindingR, pseudCommit),
            "SM: no flagged grounds"
        );

        delete _sessions[account][policyId];
        delete _pending[account][policyId];
        sessionNonce[account] += 1;
        emit SessionRevoked(account, policyId, msg.sender);
    }

    /// @notice Digest the TM should attest next: the STAGED session when a renewal is staged
    ///         (the live one is attested by construction in that case), otherwise the live one.
    function sessionDigestOf(address account, bytes32 policyId) public view returns (bytes32) {
        UserSession storage staged = _pending[account][policyId];
        if (staged.validUntil != 0) return _digestOf(account, staged);
        return _digestOf(account, _sessions[account][policyId]);
    }

    function liveSessionDigestOf(address account, bytes32 policyId) external view returns (bytes32) {
        return _digestOf(account, _sessions[account][policyId]);
    }

    function pendingSessionDigestOf(address account, bytes32 policyId) external view returns (bytes32) {
        return _digestOf(account, _pending[account][policyId]);
    }

    function _digestOf(address account, UserSession storage s) private view returns (bytes32) {
        return keccak256(abi.encode(
            account, s.policyId, s.policyVersion, s.validUntil, s.gatedContract, s.ordb, s.encryptedPseudonym
        ));
    }

    /// @dev Binding guards, account-side (handoff/03 §9.2; adversarially validated). `account` is
    ///      msg.sender on the direct path and the EIP-712 signer on the relayed one.
    function _checkAccountBindings(address account, uint64 validUntil, uint256[19] calldata pub) private view {
        require(pub[0] == uint256(uint160(account)), "SM: account binding");
        require(pub[1] == block.chainid, "SM: chainId binding");
        require(pub[2] == uint256(uint160(address(this))), "SM: SM binding");
        require(pub[4] == uint256(validUntil), "SM: validUntil binding");
        require(validUntil > block.timestamp, "SM: expired validUntil");
        require(pub[5] == sessionNonce[account], "SM: nonce binding");
    }

    /// @dev Live root pinning: the policy names its sources (P0-6).
    function _checkPolicyBindings(
        bytes32 policyId,
        uint32 policyVersion,
        uint64 validUntil,
        uint256[19] calldata pub
    ) private view {
        // New grants must target the CURRENT policy version, otherwise a strengthened policy
        // could be sidestepped forever by proving against a weaker historical version (internal review).
        // Already-granted sessions still run to expiry (P1-8 non-retroactivity is unchanged).
        require(policyVersion == policyRegistry.latestVersion(policyId), "SM: stale policy version");
        (
            UserPolicyRegistry.IdentityRootSource[2] memory roots,
            address requiredORDB,
            ,
            bytes32 clausesHash,
            uint64 maxSessionValidity
        ) = policyRegistry.getPolicyVersion(policyId, policyVersion);

        require(pub[3] == uint256(clausesHash), "SM: predicate binding");
        require(uint256(validUntil) <= block.timestamp + maxSessionValidity, "SM: exceeds policy cap");
        require(pub[6] == uint256(didRegistry.root()), "SM: stale DID root");
        for (uint256 i = 0; i < 2; i++) {
            uint256 o = 7 + i * 3;
            require(pub[o] == uint256(uint160(roots[i].ita)), "SM: ITA binding");
            require(pub[o + 1] == uint256(roots[i].regimeHash), "SM: regime binding");
            require(
                pub[o + 2] == uint256(IdentityAnchor(roots[i].ita).getAttributeRegimeRoot(roots[i].regimeHash)),
                "SM: stale credential root"
            );
        }
        _checkOrdbBindings(requiredORDB, pub);
    }

    function _checkOrdbBindings(address requiredORDB, uint256[19] calldata pub) private view {
        OnchainRiskDatabase ordb = OnchainRiskDatabase(requiredORDB);
        require(pub[13] == uint256(uint160(requiredORDB)), "SM: ORDB binding");
        require(pub[14] == uint256(ordb.root()), "SM: stale risk root");
        require(pub[15] == uint256(uint160(ordb.monitoredContract())), "SM: gated-contract binding");
        (,, bytes32 keyId) = ordb.getMonitorKey();
        require(pub[18] == uint256(keyId), "SM: monitor key binding");
    }

    /// @notice The TF hot path: a single expiry compare (P1-8), the session must have been
    ///         proven FOR this contract (internal review finding: prevents cross-contract session reuse when
    ///         two contracts share a policyId), and it must be TM-attested (GAP-H3). Staged
    ///         renewals are invisible here: only the live slot can ever satisfy the filter.
    function hasValidSession(address account, bytes32 policyId, address gatedContract)
        external view returns (bool)
    {
        UserSession storage s = _sessions[account][policyId];
        return s.validUntil >= block.timestamp && s.gatedContract == gatedContract && s.attested;
    }

    function getSession(address account, bytes32 policyId) external view returns (UserSession memory) {
        return _sessions[account][policyId];
    }

    function getPendingSession(address account, bytes32 policyId) external view returns (UserSession memory) {
        return _pending[account][policyId];
    }

    // ---------- Contract Sessions (P1-14) ----------

    /// @notice Permissionless index of a Classification-store entry. Grants nothing by itself:
    ///         validity is re-read LIVE from the store at every check (handoff/03 §9.3).
    /// @dev    The entry goes in its issuing CTA's list. A full list first drops its revoked
    ///         entries, so the renewal flow (revoke, then certify a new index) never exhausts it.
    function registerContractSession(address target, uint256 credentialIdx) external {
        require(credentialIdx < classificationStore.classificationCount(target), "SM: bad idx");
        address cta = classificationStore.getClassification(target, credentialIdx).cta;
        ContractSession[] storage list = _contractSessions[target][cta];
        for (uint256 i = 0; i < list.length; i++) {
            require(list[i].credentialIdx != credentialIdx, "SM: duplicate contract session"); // dedup (internal review)
        }
        if (list.length >= MAX_CONTRACT_SESSIONS) _dropRevoked(target, list);
        require(list.length < MAX_CONTRACT_SESSIONS, "SM: too many contract sessions"); // anti-griefing (internal review)
        list.push(ContractSession(credentialIdx, true));
        emit ContractSessionRegistered(target, cta, credentialIdx);
    }

    /// @dev Swap-and-pop every entry the store reports revoked. Order is not meaningful: the check
    ///      below accepts ANY valid entry.
    function _dropRevoked(address target, ContractSession[] storage list) private {
        uint256 i = 0;
        while (i < list.length) {
            if (classificationStore.getClassification(target, list[i].credentialIdx).revoked) {
                list[i] = list[list.length - 1];
                list.pop();
            } else {
                i++;
            }
        }
    }

    function hasValidContractSession(address target, ContractRequirement calldata req)
        external view returns (bool)
    {
        // Only the accepted CTAs' lists are read, so an entry from any other anchor is never even
        // loaded, and every entry read here was issued by an accepted CTA by construction.
        for (uint256 j = 0; j < req.acceptedCTAs.length; j++) {
            ContractSession[] storage list = _contractSessions[target][req.acceptedCTAs[j]];
            for (uint256 i = 0; i < list.length; i++) {
                ClassificationContract.Classification memory c =
                    classificationStore.getClassification(target, list[i].credentialIdx);
                if (c.regimeHash != req.regimeHash || c.class != req.class) continue;
                // live re-validation against the store + live EXTCODEHASH
                if (classificationStore.isClassificationValid(
                        target, list[i].credentialIdx, req.requireCodeMatch, req.maxAge,
                        req.requireImmutableCode)) {
                    return true;
                }
            }
        }
        return false;
    }

    function contractSessionCount(address target, address cta) external view returns (uint256) {
        return _contractSessions[target][cta].length;
    }
}
