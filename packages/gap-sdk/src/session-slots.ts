// The ONE mirror of `SessionManager`'s two-slot session storage.
//
// `SessionManager` keeps TWO slots per (account, policyId):
//   * the LIVE slot (`_sessions`): the only slot `hasValidSession` reads, so the only slot that
//     gates a transfer;
//   * the STAGING slot (`_pending`), where `_install` writes a re-grant when the live session is
//     still ATTESTED and UNEXPIRED, so that an early renewal cannot destroy a working session.
//
// `sessionDigestOf` NAMES the staged session whenever one exists, and `attestSession` promotes
// that stage into the live slot atomically. So "the session the contract is talking about" is the
// staged one on any deployment where two runs can fall inside one session TTL.
//
// WHY THIS MODULE EXISTS. That selection rule had been restated per cell, and every restatement
// that read only `getSession` produced the same defect: fields describing the LIVE session paired
// with a digest naming the STAGED one. The TM decrypted the wrong ciphertext; the holder gateway
// 409'd every legitimate renewal; the CLI attested, and therefore PROMOTED: a session whose
// ciphertext it had never opened. One shared selector removes the class: a caller cannot obtain a
// session without also obtaining THAT session's digest, because `inspectNamedSession` returns
// them together and refuses to let them disagree with the contract.
//
// Nothing here is a policy. It reports FACTS about the named slot; each cell still applies its own
// guards, in its own order, with its own error vocabulary.

import { encodeAbiParameters, keccak256, type Address, type Hex } from "viem";

/**
 * The reads any cell needs to see both slots, as human-readable ABI signatures.
 *
 * Shared so that no cell can declare `getSession` without also being handed `getPendingSession`
 * and `sessionDigestOf`: the missing `getPendingSession` entry was the STRUCTURAL half of this
 * defect: cells physically could not see the staging slot.
 *
 * Spread into the cell's own `parseAbi([...])` alongside whatever else it calls.
 */
export const SESSION_SLOT_ABI_SIGNATURES = [
  "function getSession(address account,bytes32 policyId) view returns ((uint64 validUntil,bytes32 policyId,uint32 policyVersion,address gatedContract,address ordb,bool attested,bytes encryptedPseudonym))",
  "function getPendingSession(address account,bytes32 policyId) view returns ((uint64 validUntil,bytes32 policyId,uint32 policyVersion,address gatedContract,address ordb,bool attested,bytes encryptedPseudonym))",
  "function sessionDigestOf(address account,bytes32 policyId) view returns (bytes32)",
] as const;

/** A session as `getSession` / `getPendingSession` return it, minus the attestation flag. */
export interface StoredSessionView {
  policyId: Hex;
  policyVersion: bigint | number;
  validUntil: bigint | number;
  gatedContract: Hex;
  ordb: Hex;
  encryptedPseudonym: Hex;
}

/** A whole session slot, exactly as either getter returns it. */
export interface SessionSlotView extends StoredSessionView {
  readonly attested: boolean;
}

/** Both slots plus the digest the CONTRACT says is next to attest, read together. */
export interface SessionSlots {
  readonly live: SessionSlotView;
  readonly pending: SessionSlotView;
  /** `sessionDigestOf(account, policyId)`. */
  readonly named: Hex;
}

/** The deployment scope a session must have been proven for, when a caller enforces one. */
export interface SessionScope {
  readonly policyId: Hex;
  /** pub[15]: the contract the session gates (the shared scope anchor, token, or venue). */
  readonly gatedContract: Address;
  readonly ordb: Address;
}

/**
 * Everything true about the slot the contract NAMES, established in one place.
 *
 * `session` and `digest` are the same slot by construction: that is the whole point. There is no
 * way to get one without the other, so no caller can re-create the pairing bug.
 */
export interface NamedSessionCheck {
  /** The session `sessionDigestOf` names: the stage when one exists, the live slot otherwise. */
  readonly session: SessionSlotView;
  /** `session`'s digest, recomputed here from `session`'s own fields. */
  readonly digest: Hex;
  /** True when the named slot is the staging slot, i.e. attesting `digest` PROMOTES it. */
  readonly staged: boolean;
  /** `validUntil != 0`: a slot that has ever been written. */
  readonly present: boolean;
  /** `session.attested`. False for a stage by construction: `_install` never writes true. */
  readonly attested: boolean;
  /** `validUntil < nowSeconds`, or null when the caller supplied no clock. */
  readonly expired: boolean | null;
  /** Whether `session` matches the caller's scope, or null when the caller supplied none. */
  readonly inScope: boolean | null;
  /**
   * Whether the recomputed digest equals `sessionDigestOf`.
   *
   * False means the slots moved between reads (a grant landed mid-batch) or the contract's digest
   * preimage has drifted from ours. Either way the caller cannot say WHICH session it is looking
   * at and must refuse rather than guess.
   */
  readonly digestMatchesNamed: boolean;
}

const DIGEST_PARAMETERS = [
  { type: "address" },
  { type: "bytes32" },
  { type: "uint32" },
  { type: "uint64" },
  { type: "address" },
  { type: "address" },
  { type: "bytes" },
] as const;

const lower = (value: string): Address => value.toLowerCase() as Address;

const sameAddress = (left: string, right: string): boolean =>
  left.toLowerCase() === right.toLowerCase();

/**
 * `SessionManager._digestOf` recomputed off-chain, over the SAME preimage.
 *
 * Recomputing rather than only trusting `sessionDigestOf` is what lets a caller say WHICH slot
 * the contract named, and it doubles as a drift alarm: if the contract ever changes the preimage
 * this stops agreeing and callers refuse instead of acting blind.
 *
 * Note the preimage excludes `attested`, so a promoted session keeps the digest it was validated
 * under, which is what makes a post-promotion readback self-verifying.
 */
export function computeSessionDigest(account: Address, session: SessionSlotView): Hex {
  return keccak256(encodeAbiParameters(DIGEST_PARAMETERS, [
    // Lower-cased before encoding: the digest is over the 20 bytes, but viem's encoder rejects a
    // mixed-case address whose EIP-55 checksum does not verify. Reads come back checksummed and
    // would pass; anything hand-built or re-cased would not, and failing on presentation rather
    // than on value would be a footgun in a security-critical helper.
    lower(account),
    session.policyId,
    Number(session.policyVersion),
    BigInt(session.validUntil),
    lower(session.gatedContract),
    lower(session.ordb),
    session.encryptedPseudonym,
  ]));
}

/**
 * The slot the contract names, and nothing else.
 *
 * Mirrors `sessionDigestOf` / `attestSession` exactly: the stage when `_pending.validUntil != 0`,
 * the live slot otherwise. Prefer `inspectNamedSession`, which also binds the digest.
 */
export function selectNamedSessionSlot(
  slots: Pick<SessionSlots, "live" | "pending">,
): { readonly session: SessionSlotView; readonly staged: boolean } {
  const staged = BigInt(slots.pending.validUntil) !== 0n;
  return { session: staged ? slots.pending : slots.live, staged };
}

/**
 * Resolve the named slot and establish every fact a caller might guard on.
 *
 * Supply `nowSeconds` to have expiry evaluated and `scope` to have the deployment binding
 * evaluated; omit either and the corresponding fact is `null` (NOT CHECKED), never a silent pass.
 */
export function inspectNamedSession(
  account: Address,
  slots: SessionSlots,
  options: {
    readonly nowSeconds?: bigint;
    readonly scope?: SessionScope;
  } = {},
): NamedSessionCheck {
  const { session, staged } = selectNamedSessionSlot(slots);
  const validUntil = BigInt(session.validUntil);
  const digest = computeSessionDigest(account, session);
  return {
    session,
    digest,
    staged,
    present: validUntil !== 0n,
    attested: session.attested,
    expired: options.nowSeconds === undefined ? null : validUntil < options.nowSeconds,
    inScope: options.scope === undefined ? null : (
      sameAddress(session.policyId, options.scope.policyId)
      && sameAddress(session.gatedContract, options.scope.gatedContract)
      && sameAddress(session.ordb, options.scope.ordb)
    ),
    digestMatchesNamed: sameAddress(digest, slots.named),
  };
}
