import { createHmac, timingSafeEqual } from "node:crypto";
import { toBytes32 } from "./field";
import type { Bytes32 } from "./types";

/**
 * Per-person DID derivation (one human = one DID).
 *
 * The DID is public on-chain, so an unkeyed H(accountLinkId) would let anyone
 * holding or guessing a platform customer-link id link on-chain credentials to
 * that customer. The derivation is therefore keyed with an IK-held secret that
 * is never logged and whose rotation is an explicit migration.
 */
export const PERSON_DID_DOMAIN = "DSI_PERSON_DID_V1";

/** Canonical lowercase UUIDv4: the single lexical form of a customer-link id. */
export const CANONICAL_SUBJECT_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isCanonicalSubjectId(value: unknown): value is string {
  return typeof value === "string" && CANONICAL_SUBJECT_ID.test(value);
}

export interface PersonDidInput {
  /** 32-byte IK-held secret. Pinned by config digest; rotation re-identifies everyone. */
  readonly personDidKey: Uint8Array;
  /** Provider environment, NOT chain id, anchor, regime, or product. */
  readonly environment: "sandbox";
  /** The onboarding platform's customer-link id == the provider applicant externalUserId. */
  readonly accountLinkId: string;
}

/**
 * Mask to 253 bits. 2^253 < BN254_FIELD, so the result is in-field with zero
 * modular bias, unlike reducing a full 256-bit digest mod p, where residues
 * below 2^256 mod p would be ~25% more likely.
 */
const FIELD_MASK = (1n << 253n) - 1n;

export function derivePersonDid(input: PersonDidInput): Bytes32 {
  if (!(input.personDidKey instanceof Uint8Array) || input.personDidKey.length !== 32) {
    throw new Error("personDidKey must be exactly 32 bytes");
  }
  if (input.environment !== "sandbox") throw new Error("unsupported person DID environment");
  if (!isCanonicalSubjectId(input.accountLinkId)) {
    throw new Error("accountLinkId must be a canonical lowercase UUIDv4");
  }
  const preimage = JSON.stringify([PERSON_DID_DOMAIN, input.environment, input.accountLinkId]);
  const raw = createHmac("sha256", input.personDidKey).update(preimage, "utf8").digest("hex");
  const value = BigInt(`0x${raw}`) & FIELD_MASK;
  // Probability 2^-253. Never substitute a fallback: a zero DID is unreachable,
  // and silently mapping it would collide every such person onto one identity.
  if (value === 0n) throw new Error("derived person DID is zero");
  return toBytes32(value);
}

/**
 * Constant-time cross-check that a supplied DID equals the derivation. Used so
 * a configured/bootstrapped DID becomes a *verified* value rather than a
 * trusted input.
 */
export function assertDerivedPersonDid(supplied: string, input: PersonDidInput): Bytes32 {
  const derived = derivePersonDid(input);
  const left = Buffer.from(derived.slice(2), "hex");
  let right: Buffer;
  try {
    right = Buffer.from(supplied.toLowerCase().replace(/^0x/, ""), "hex");
  } catch {
    throw new Error("supplied DID is not hex");
  }
  if (right.length !== 32 || !timingSafeEqual(left, right)) {
    throw new Error("supplied DID does not match the derived per-person DID");
  }
  return derived;
}

/**
 * How the holder's salt is held. Single-sourced here so a stamp written by the CLI and a model
 * recorded by the Keeper cannot drift into two spellings of one fact.
 *
 * This lived in `gap-platform-core`, which carried a `CustodyModelRegistry` treating a change of
 * model as a migration rather than an edit. That package was reference material from the full
 * stack, composed by nothing here, and this three-value union was the only thing in it that
 * anything imported, so the package went and the vocabulary stayed.
 */
export type CustodyModel = "IK_HELD" | "IK_CUSTODY_DEMO" | "CLIENT_HELD";

const CUSTODY_MODELS: readonly CustodyModel[] = ["IK_HELD", "IK_CUSTODY_DEMO", "CLIENT_HELD"];

export function isCustodyModel(value: unknown): value is CustodyModel {
  return typeof value === "string" && (CUSTODY_MODELS as readonly string[]).includes(value);
}
