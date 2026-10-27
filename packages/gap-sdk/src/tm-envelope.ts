// The ONE definition of the TM session envelope.
//
// A granted session stores `encryptedPseudonym = abi.encode(pub[16], pub[17], pub[18],
// ciphertext)` (SessionManager `_install`). The prover produces the inner `ciphertext`; the
// transaction monitor opens it. Both sides need the SAME two things:
//
//   1. the outer envelope layout, and
//   2. the AEAD associated data that names the session the envelope was sealed for.
//
// Before this module the prover built (2) from its witness and the TM re-stated the layout of
// (1) by hand in `session-attestor.ts` (full stack, not in this repository), two mirrors of one format, which is exactly how the
// TM ended up only ever accepting the insecure cleartext envelope. Both now import from here,
// and `tmSessionContext` is the single constructor for the associated data, so a field that is
// added, reordered or dropped changes both sides at once or neither.
//
// Nothing here holds key material: this is layout and binding only.

import { decodeAbiParameters } from "viem";
import { hexToBytes } from "./random";
import type { StoredSessionView } from "./session-slots";
import type { Hex, TmEncryptionContext, WitnessData } from "./types";

/** The outer, contract-written envelope around the AEAD ciphertext. */
export interface SessionEnvelope {
  /** pub[16], Poseidon(pseudonym, blindingR), as proven. */
  pseudonymCommitment: bigint;
  /** pub[17], Poseidon(ita0, ikId0), as proven. */
  ikRefCommitment: bigint;
  /** pub[18]: the ORDB monitor key the session was proven against. */
  monitorKeyId: bigint;
  /** The sealed payload the monitor decrypts. */
  ciphertext: Hex;
}

const ENVELOPE_ABI = [
  { type: "uint256" },
  { type: "uint256" },
  { type: "uint256" },
  { type: "bytes" },
] as const;

/** Decode a session's stored `encryptedPseudonym`. Throws on any foreign/legacy shape. */
export function decodeSessionEnvelope(encryptedPseudonym: Hex): SessionEnvelope {
  let decoded: readonly [bigint, bigint, bigint, Hex];
  try {
    decoded = decodeAbiParameters(ENVELOPE_ABI, encryptedPseudonym) as
      readonly [bigint, bigint, bigint, Hex];
  } catch {
    throw new Error("GAP SDK: stored session envelope is not decodable");
  }
  return {
    pseudonymCommitment: decoded[0],
    ikRefCommitment: decoded[1],
    monitorKeyId: decoded[2],
    ciphertext: decoded[3],
  };
}

/**
 * The session an envelope is sealed for, in the one shape both sides map onto.
 *
 * The prover has these as witness fields; the monitor reads them back from its configuration,
 * the stored session and the envelope. Addresses/ids are accepted either as bigints (prover
 * side) or as 0x strings (chain-read side) so that neither caller has to pre-convert and get
 * the conversion subtly wrong.
 */
export interface TmSessionSource {
  chainId: bigint | number;
  sessionManager: bigint | Hex;
  account: bigint | Hex;
  policyId: bigint | Hex;
  policyVersion: bigint | number;
  validUntil: bigint | number;
  accountNonce: bigint | number;
  ordb: bigint | Hex;
  gatedContract: bigint | Hex;
  monitorKeyId: bigint | Hex;
  pseudonymCommitment: bigint;
  ikRefCommitment: bigint;
}

function field(value: bigint | number | Hex, label: string): bigint {
  const parsed = BigInt(value);
  if (parsed < 0n) throw new Error(`GAP SDK: ${label} must not be negative`);
  return parsed;
}

/**
 * The AEAD associated data for a session: the single constructor both sides use.
 *
 * Every field here is authenticated but not encrypted: a monitor that decrypts successfully
 * has proven the envelope was sealed for exactly this session on exactly this chain, and a
 * ciphertext lifted onto any other session (or any other monitor key) fails to authenticate.
 */
export function tmSessionContext(source: TmSessionSource): TmEncryptionContext {
  return {
    chainId: field(source.chainId, "chainId"),
    sessionManager: field(source.sessionManager, "sessionManager"),
    account: field(source.account, "account"),
    policyId: field(source.policyId, "policyId"),
    policyVersion: field(source.policyVersion, "policyVersion"),
    validUntil: field(source.validUntil, "validUntil"),
    accountNonce: field(source.accountNonce, "accountNonce"),
    ordb: field(source.ordb, "ordb"),
    gatedContract: field(source.gatedContract, "gatedContract"),
    monitorKeyId: field(source.monitorKeyId, "monitorKeyId"),
    pseudonymCommitment: source.pseudonymCommitment,
    ikRefCommitment: source.ikRefCommitment,
  };
}

/** Prover side: the context for the session this witness is about to grant. */
export function tmSessionContextForWitness(
  witness: WitnessData,
  commitments: { pseudonymCommitment: bigint; ikRefCommitment: bigint },
): TmEncryptionContext {
  return tmSessionContext({
    chainId: witness.chainId,
    sessionManager: witness.sessionManager,
    account: witness.account,
    policyId: witness.policyId,
    policyVersion: witness.policyVersion,
    validUntil: witness.validUntil,
    accountNonce: witness.accountNonce,
    ordb: witness.ordbId,
    gatedContract: witness.gatedContract,
    monitorKeyId: witness.monitorKeyId,
    ...commitments,
  });
}

/**
 * A session as the monitor reads it back from either slot getter.
 *
 * Defined in `./session-slots`, which owns everything about `SessionManager`'s two-slot storage;
 * re-exported here because the envelope is sealed per session and callers of this module already
 * hold one. Which slot it came from is `session-slots`' business, never this module's.
 */
export type { StoredSessionView } from "./session-slots";

/**
 * Monitor side: the envelope plus the context it must have been sealed under.
 *
 * `accountNonce` is the only field the monitor cannot read straight back off the session: the
 * grant binds `pub[5] == sessionNonce[account]` and then `_install` increments it, so the value
 * the prover sealed under is the counter as it stood BEFORE that grant. Callers supply the
 * candidate; see `grantNonceCandidates`.
 */
export function tmSessionContextForStoredSession(args: {
  chainId: bigint | number;
  sessionManager: Hex;
  account: Hex;
  accountNonce: bigint | number;
  session: StoredSessionView;
}): { envelope: SessionEnvelope; context: TmEncryptionContext } {
  const envelope = decodeSessionEnvelope(args.session.encryptedPseudonym);
  return {
    envelope,
    context: tmSessionContext({
      chainId: args.chainId,
      sessionManager: args.sessionManager,
      account: args.account,
      policyId: args.session.policyId,
      policyVersion: args.session.policyVersion,
      validUntil: args.session.validUntil,
      accountNonce: args.accountNonce,
      ordb: args.session.ordb,
      gatedContract: args.session.gatedContract,
      monitorKeyId: envelope.monitorKeyId,
      pseudonymCommitment: envelope.pseudonymCommitment,
      ikRefCommitment: envelope.ikRefCommitment,
    }),
  };
}

/**
 * The account nonces a still-unattested session could have been granted under, newest first.
 *
 * Every grant bumps `sessionNonce` and writes an UNATTESTED session into ONE of the two slots
 * (`_install`): over the live slot when nothing is live and attested, into the staging slot when
 * something is. Either way the newest grant for an account is the newest unattested session, so
 * the session the contract NAMES (`session-slots.inspectNamedSession`) was granted under
 * `sessionNonce - 1`. That is the first candidate and the one that matches in every ordinary run.
 *
 * The short tail exists only so a grant that raced the monitor's reads does not wedge attestation
 *, and, on a persistent deployment, so a stage granted a moment before an unrelated grant on the
 * same account still opens. It is a liveness aid, never a relaxation: a candidate is accepted only
 * if the AEAD tag authenticates under it, and no nonce lets a forged envelope authenticate.
 */
export const MAX_GRANT_NONCE_LOOKBACK = 4;

export function grantNonceCandidates(
  sessionNonce: bigint,
  lookback = MAX_GRANT_NONCE_LOOKBACK,
): bigint[] {
  const candidates: bigint[] = [];
  for (let back = 1n; back <= BigInt(lookback); back += 1n) {
    const candidate = sessionNonce - back;
    if (candidate < 0n) break;
    candidates.push(candidate);
  }
  return candidates;
}

/** The sealed payload as bytes, ready for `decryptBabyJubTmCiphertext`. */
export function sessionEnvelopeCiphertextBytes(envelope: SessionEnvelope): Uint8Array {
  return hexToBytes(envelope.ciphertext);
}
