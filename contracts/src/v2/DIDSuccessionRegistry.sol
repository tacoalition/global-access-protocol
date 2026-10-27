// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

/**
 * @title DIDSuccessionRegistry
 * @notice The on-chain record that ONE identity superseded another, and nothing else. A holder
 *         who loses their device (or whose salt is compromised) is re-onboarded under a NEW DID,
 *         and this registry is where that fact is anchored so a later audit can be shown the link
 *         it was told about, without the chain publishing who succeeded whom.
 * @dev WHAT IS STORED IS A COMMITMENT AND ONLY A COMMITMENT.
 *
 *      `commitment = keccak256(abi.encode(SUPERSESSION_DOMAIN, oldDid, newDid, nonce))`, folded
 *      OFF CHAIN by the Identity Keeper's supersession ladder and handed here as one opaque word.
 *      The pair is deliberately NOT an argument of any function on this contract: a `bytes32 did`
 *      parameter would put both identities in public calldata, which is exactly the linkage this
 *      design exists to withhold. The `nonce` is what stops a guessing attack: the DID set is
 *      small and enumerable in a demo topology, so without it an observer could brute-force the
 *      fold; with it, the commitment is meaningless to anyone the IK has not told.
 *
 *      THE COST OF THAT PRIVACY, NAMED. Because the contract cannot see the DIDs, it cannot
 *      enforce "one live successor per identity", cannot refuse a cycle, and cannot answer "who
 *      supersedes X". Those are the IK ladder's invariants, held in its durable state, and this
 *      registry is the anchor for them rather than their referee. Anyone who claims otherwise
 *      from an on-chain read is reading something that is not here.
 *
 *      NO ENUMERATION. There is no array of commitments and no per-DID index, only a keyed
 *      lookup for a commitment a reader was already told, plus a bare count. An enumerable list
 *      would hand an observer the full supersession set to correlate against DID registrations by
 *      block height, which is a linkage of a different shape but the same consequence.
 *
 *      AUTHORIZED WRITERS, per the v2 role pattern (`OnchainRiskDatabase`'s owner/TM split): the
 *      owner grants and revokes; an authorized writer commits. A stranger's write reverts, so a
 *      succession anchor cannot be minted by anyone who did not run the recovery.
 */
contract DIDSuccessionRegistry {
    /// @notice The domain tag folded into every succession commitment (`GAP_DID_SUPERSESSION_V1`).
    /// @dev Mirrored off chain by `services/gap-ik-api/src/succession/commitment.ts` (full stack, not in this repository); the two are
    ///      pinned to one shared test vector on both sides.
    bytes32 public constant SUPERSESSION_DOMAIN = keccak256("GAP_DID_SUPERSESSION_V1");

    struct Succession {
        /// @dev The FIRST commit's block time. A replay never rewrites it, see `commitSuccession`.
        uint64 committedAt;
        address writer;
    }

    address public owner;
    mapping(address => bool) public isWriter;
    mapping(bytes32 => Succession) private _successions;

    /// @notice How many distinct successions have been committed. A count, never a directory.
    uint256 public successionCount;

    event SuccessionCommitted(bytes32 indexed commitment, address indexed writer);
    event SuccessionWriterUpdated(address indexed writer, bool authorized);

    modifier onlyOwner() {
        require(msg.sender == owner, "DSR: not owner");
        _;
    }

    modifier onlyWriter() {
        require(isWriter[msg.sender], "DSR: not succession writer");
        _;
    }

    /// @param _owner Grants and revokes succession writers.
    /// @param firstWriter The Identity Keeper key that runs the supersession ladder. May be zero
    ///        for a deployment that authorizes its writers afterwards.
    constructor(address _owner, address firstWriter) {
        require(_owner != address(0), "DSR: zero owner");
        owner = _owner;
        if (firstWriter != address(0)) {
            isWriter[firstWriter] = true;
            emit SuccessionWriterUpdated(firstWriter, true);
        }
    }

    /// @notice Authorize or revoke a succession writer.
    /// @param writer The key that may commit succession commitments.
    /// @param authorized True to grant, false to revoke.
    function setWriter(address writer, bool authorized) external onlyOwner {
        require(writer != address(0), "DSR: zero writer");
        isWriter[writer] = authorized;
        emit SuccessionWriterUpdated(writer, authorized);
    }

    /**
     * @notice Anchor one supersession, as an opaque commitment.
     * @dev IDEMPOTENT, BECAUSE A RECOVERY LADDER RE-DRIVES. The Identity Keeper's ladder persists
     *      its intent before broadcasting and resumes after a crash, so this call WILL arrive
     *      twice for one supersession. A second commit therefore emits nothing, counts nothing,
     *      and leaves the original timestamp and writer standing: a second `SuccessionCommitted`
     *      would read, to every downstream indexer, as a second recovery for the same holder.
     *      Reverting instead would be worse: it would make the honest resume indistinguishable
     *      from a genuine conflict.
     * @param commitment The `GAP_DID_SUPERSESSION_V1` fold. Never the DIDs themselves.
     * @return created True on the first commit of this commitment, false for a replay.
     */
    function commitSuccession(bytes32 commitment) external onlyWriter returns (bool created) {
        require(commitment != bytes32(0), "DSR: zero commitment");
        if (_successions[commitment].committedAt != 0) return false;
        _successions[commitment] = Succession(uint64(block.timestamp), msg.sender);
        successionCount++;
        emit SuccessionCommitted(commitment, msg.sender);
        return true;
    }

    // ---------- views ----------

    /// @notice Whether this exact commitment has been anchored. Answers nothing about a DID.
    function isCommitted(bytes32 commitment) external view returns (bool) {
        return _successions[commitment].committedAt != 0;
    }

    /// @notice When the commitment was FIRST anchored, or 0 for one this registry has not seen.
    function committedAt(bytes32 commitment) external view returns (uint64) {
        return _successions[commitment].committedAt;
    }

    /// @notice Which authorized writer anchored it, or the zero address if none did.
    function committedBy(bytes32 commitment) external view returns (address) {
        return _successions[commitment].writer;
    }
}
