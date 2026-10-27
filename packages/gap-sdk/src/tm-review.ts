/**
 * THE MONITOR'S HALF OF A SESSION GRANT.
 *
 * A grant takes two parties. The holder's wallet proves and calls `grantSession`; the session is
 * then installed UNATTESTED and is unusable until the ORDB's Transaction Monitor opens the sealed
 * envelope, confirms it reopens the commitments the proof already committed to, and attests
 * (GAP-H3). The point of the second step is that the monitor decides independently, so it must
 * not take anything from the party asking to be attested.
 *
 * The CLI used to inline this, building the AEAD context out of the `pub` array handed to it by the
 * submitter. That is weaker than it looks: a monitor authenticating against data supplied by the
 * submitter is authenticating against nothing, and the only reason it held up is that the opened
 * plaintext was then checked against the CONTRACT-written envelope. This reads everything from the
 * stored session instead, which is the shape the rest of this module was already built for and
 * which nothing used.
 *
 * Pure, and deliberately so: a decision with no chain writes in it can be tested against a tampered
 * envelope, a foreign key and a wrong context. Those refusals were previously unreachable.
 */
import { GapSdkError } from "./errors";
import { decryptBabyJubTmCiphertext } from "./tm-cipher";
import {
  grantNonceCandidates,
  MAX_GRANT_NONCE_LOOKBACK,
  sessionEnvelopeCiphertextBytes,
  tmSessionContextForStoredSession,
  type SessionEnvelope,
} from "./tm-envelope";
import type { StoredSessionView } from "./session-slots";
import type { Hex, TmEncryptionContext, TmEncryptionPlaintext } from "./types";

/**
 * The two Poseidon widths the commitments need, injected rather than imported.
 *
 * This package is config-injected by design and must not reach into `circuits/`. The caller passes
 * the same Poseidon the circuit uses; a mismatched one fails the reopen check rather than silently
 * accepting, because the committed values come from the chain.
 */
export interface TmPoseidon {
  h2(a: bigint, b: bigint): Promise<bigint>;
  h3(a: bigint, b: bigint, c: bigint): Promise<bigint>;
}

export interface StoredSessionReview {
  /** The contract-written envelope: `abi.encode(pub[16], pub[17], pub[18], ciphertext)`. */
  envelope: SessionEnvelope;
  /** What the monitor recovered. Never logged by this module: it de-anonymises the holder. */
  opened: TmEncryptionPlaintext;
  /** The context the envelope actually authenticated under. */
  context: TmEncryptionContext;
  /** The grant nonce that worked, for callers that want to record which candidate matched. */
  accountNonce: bigint;
}

/**
 * Decide whether a stored session may be attested, reading only the chain and the monitor's key.
 *
 * Throws `GapSdkError("CIPHERTEXT_INVALID")` with a message naming which of the three distinct
 * failures occurred, because conflating them is how a monitor ends up reporting "bad key" for a
 * forged envelope.
 */
export async function reviewStoredSession(args: {
  chainId: bigint | number;
  sessionManager: Hex;
  account: Hex;
  /** `sessionNonce(account)` read AFTER the grant, `_install` has already incremented it. */
  sessionNonce: bigint;
  session: StoredSessionView;
  monitorScalar: bigint;
  hash: TmPoseidon;
  /**
   * The ORDB's LIVE monitor key id, when the caller can read it.
   *
   * The envelope's own id was written by the contract from `pub[18]`, and the grant required that
   * to equal the ORDB's key id AT THE TIME. A key rotation since then leaves a session proven
   * against a key the ORDB no longer publishes, and it would still open, because the AEAD key is
   * derived from the id in the envelope, so a monitor still holding the old scalar sees nothing
   * wrong. This is the only check that refuses it.
   */
  expectedMonitorKeyId?: bigint;
  lookback?: number;
}): Promise<StoredSessionReview> {
  const candidates = grantNonceCandidates(
    args.sessionNonce,
    args.lookback ?? MAX_GRANT_NONCE_LOOKBACK,
  );
  if (candidates.length === 0) {
    throw new GapSdkError(
      "CIPHERTEXT_INVALID",
      "no grant nonce to attest under, the account has never been granted a session",
    );
  }

  // The candidate list is a LIVENESS aid, never a relaxation. A grant that raced the monitor's
  // reads, or an unrelated grant on the same account, moves the counter past the value the prover
  // sealed under. Every candidate still has to authenticate the AEAD tag, and no nonce makes a
  // forged envelope authenticate, so trying several costs nothing in soundness.
  let envelope: SessionEnvelope | undefined;
  let opened: TmEncryptionPlaintext | undefined;
  let context: TmEncryptionContext | undefined;
  let accountNonce = 0n;
  let lastFailure: unknown;

  for (const candidate of candidates) {
    const derived = tmSessionContextForStoredSession({
      chainId: args.chainId,
      sessionManager: args.sessionManager,
      account: args.account,
      accountNonce: candidate,
      session: args.session,
    });
    envelope = derived.envelope;
    try {
      opened = await decryptBabyJubTmCiphertext(
        sessionEnvelopeCiphertextBytes(derived.envelope),
        args.monitorScalar,
        derived.context,
      );
      context = derived.context;
      accountNonce = candidate;
      break;
    } catch (e) {
      lastFailure = e;
    }
  }

  if (!opened || !envelope || !context) {
    throw new GapSdkError(
      "CIPHERTEXT_INVALID",
      "the stored ciphertext does not open under this monitor key and session context"
        + ` (tried ${candidates.length} grant nonce${candidates.length === 1 ? "" : "s"}), `
        + String((lastFailure as Error)?.message ?? lastFailure),
    );
  }

  if (args.expectedMonitorKeyId !== undefined
      && envelope.monitorKeyId !== args.expectedMonitorKeyId) {
    throw new GapSdkError(
      "CIPHERTEXT_INVALID",
      "refusing to attest: the session was proven against monitor key "
      + `${envelope.monitorKeyId}, and the ORDB now publishes ${args.expectedMonitorKeyId}`,
    );
  }

  // THE COMMITMENTS COME FROM THE CHAIN. `SessionManager._install` builds the envelope itself as
  // `abi.encode(pub[16], pub[17], pub[18], ciphertext)`, so these ARE the proven values and the
  // submitter never chose them. Comparing against a caller-supplied `pub` would check the
  // submitter's arithmetic against the submitter's own numbers.
  const [pseudonymCommitment, ikRefCommitment] = await Promise.all([
    args.hash.h2(opened.pseudonym, opened.blindingR),
    args.hash.h3(opened.ita0, opened.ikId0, opened.ikBlind),
  ]);
  if (pseudonymCommitment !== envelope.pseudonymCommitment) {
    throw new GapSdkError(
      "CIPHERTEXT_INVALID",
      "refusing to attest: the opened pseudonym does not reopen the proven commitment pub[16]",
    );
  }
  // pub[17] is Poseidon(ita0, ikId0, ikBlind), three inputs, blinded. A 2-ary hash of the first
  // two inverted by table lookup, since both are public, and named the Identity Keeper on-chain.
  if (ikRefCommitment !== envelope.ikRefCommitment) {
    throw new GapSdkError(
      "CIPHERTEXT_INVALID",
      "refusing to attest: the opened keeper reference does not reopen the proven commitment pub[17]",
    );
  }

  return { envelope, opened, context, accountNonce };
}
