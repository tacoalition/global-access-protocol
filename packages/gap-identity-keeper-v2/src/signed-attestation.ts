import { createPublicKey, verify as cryptoVerify } from "node:crypto";

/**
 * The signature-and-shape half of EVERY signed attestation this system accepts.
 *
 * Two authorities now sign attestations into the same trust story: the KYC
 * provider attests IDENTITY facts (`provider-attestation.ts`), and the fund IK
 * attests SUITABILITY (`./suitability-attestation.ts`). Their
 * payloads are deliberately different, different profile tag, different slot
 * count, different pinned key set, but their envelope, their canonical
 * base64url discipline, their pinned-Ed25519 rule and their positional-slot
 * decoding are the same, and a second copy of those is exactly how a verifier
 * drifts. Both call this module; neither re-implements it.
 *
 * Nothing here decides anything: it establishes only "these bytes were signed by
 * a key the operator pinned, and they decode to N well-formed slots". Every
 * semantic check (approved? fresh? about this subject?) belongs to the caller.
 */

export interface SignedAttestationEnvelope {
  readonly profile: string;
  readonly keyId: string;
  readonly payload: string;
  readonly signature: string;
}

export const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
export const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
export const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
export const SHA256_HEX_PATTERN = /^0x[0-9a-f]{64}$/;
const SLOT_UINT64_MAX = (1n << 64n) - 1n;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function decodeBase64Url(value: unknown, label: string, max: number): Buffer {
  if (typeof value !== "string" || value.length === 0 || !BASE64URL_PATTERN.test(value)) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.length > max) throw new Error(`${label} has an illegal length`);
  if (decoded.toString("base64url") !== value) throw new Error(`${label} is not canonical base64url`);
  return decoded;
}

export interface EnvelopeShape {
  /** The exact profile tag this envelope must carry. A mismatch is a refusal. */
  readonly profile: string;
  /** How the envelope is named in refusals, e.g. "provider attestation". */
  readonly noun: string;
  readonly maxPayloadBytes?: number;
}

/**
 * Envelope parse: exact key set, pinned profile tag, canonical base64url in both
 * byte fields. Unknown keys are rejected rather than ignored: an envelope that
 * carries a field this verifier does not understand has not been verified.
 */
export function parseSignedEnvelope(value: unknown, shape: EnvelopeShape): SignedAttestationEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${shape.noun} must be an object`);
  }
  const input = value as Record<string, unknown>;
  const allowed = new Set(["profile", "keyId", "payload", "signature"]);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) throw new Error(`unexpected ${shape.noun} key: ${key}`);
  }
  if (input.profile !== shape.profile) throw new Error(`${shape.noun} profile mismatch`);
  if (typeof input.keyId !== "string" || !KEY_ID_PATTERN.test(input.keyId)) {
    throw new Error(`${shape.noun} keyId is malformed`);
  }
  decodeBase64Url(input.payload, "attestation payload", shape.maxPayloadBytes ?? 4096);
  const signature = decodeBase64Url(input.signature, "attestation signature", 64);
  if (signature.length !== 64) throw new Error("attestation signature must be 64 bytes");
  return {
    profile: shape.profile,
    keyId: input.keyId,
    payload: input.payload as string,
    signature: input.signature as string,
  };
}

/**
 * Ed25519 over the exact received payload bytes, under the key pinned for this
 * keyId. An unknown keyId refuses: there is deliberately no "try every pinned
 * key" fallback, because that would let one authority's key validate another's
 * envelope.
 */
export function verifyPinnedEd25519(input: {
  readonly keyId: string;
  readonly payload: Buffer;
  readonly signature: Buffer;
  readonly publicKeys: Readonly<Record<string, string>>;
  readonly noun: string;
}): void {
  const pinned = Object.prototype.hasOwnProperty.call(input.publicKeys, input.keyId)
    ? input.publicKeys[input.keyId]
    : undefined;
  if (!pinned) throw new Error(`${input.noun} keyId ${input.keyId} is not pinned`);
  if (!/^0x[0-9a-fA-F]{64}$/.test(pinned)) throw new Error(`pinned ${input.noun} public key must be 32 bytes`);
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pinned.slice(2), "hex")]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  if (!cryptoVerify(null, input.payload, key, input.signature)) {
    throw new Error(`${input.noun} signature is invalid`);
  }
}

/**
 * Decode the canonical positional payload: a JSON array of exactly `slotCount`
 * slots whose slot 0 is the profile tag. Slot ORDER is normative for every
 * profile, positions are the schema, so a fixed length plus a pinned tag is
 * what stops one profile's bytes being read as another's.
 */
export function decodeSlotArray(input: {
  readonly payload: Buffer;
  readonly profile: string;
  readonly slotCount: number;
  readonly label?: string;
}): readonly unknown[] {
  const label = input.label ?? "attestation payload";
  let slots: unknown;
  try {
    slots = JSON.parse(input.payload.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (!Array.isArray(slots) || slots.length !== input.slotCount) {
    throw new Error(`${label} must be a ${input.slotCount}-slot array`);
  }
  if (slots[0] !== input.profile) throw new Error(`${label} profile tag mismatch`);
  return slots;
}

export function expectString(slots: readonly unknown[], index: number, label: string): string {
  const value = slots[index];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a nonempty string`);
  return value;
}

export function expectUint64(slots: readonly unknown[], index: number, label: string): bigint {
  const raw = expectString(slots, index, label);
  if (!DECIMAL_PATTERN.test(raw)) throw new Error(`${label} must be a canonical decimal uint64`);
  const parsed = BigInt(raw);
  if (parsed > SLOT_UINT64_MAX) throw new Error(`${label} exceeds uint64`);
  return parsed;
}

export function expectIsoUtc(slots: readonly unknown[], index: number, label: string): string {
  const raw = expectString(slots, index, label);
  if (!raw.endsWith("Z") || Number.isNaN(Date.parse(raw))) {
    throw new Error(`${label} must be an ISO-8601 UTC timestamp ending in Z`);
  }
  return raw;
}

/** A `"0"`/`"1"` slot as a bigint. Anything else refuses rather than coercing. */
export function expectBooleanSlot(slots: readonly unknown[], index: number, label: string): bigint {
  const raw = expectString(slots, index, label);
  if (raw !== "0" && raw !== "1") throw new Error(`${label} must be the string "0" or "1"`);
  return BigInt(raw);
}

export function epochSeconds(iso: string): bigint {
  return BigInt(Math.floor(Date.parse(iso) / 1000));
}

/**
 * Envelope → verified signature → decoded slots, in the one order that is safe:
 * the signature is checked over the received bytes BEFORE anything reads them,
 * so no decode ever runs on unauthenticated input.
 */
export function openSignedAttestation(input: unknown, shape: EnvelopeShape & {
  readonly slotCount: number;
  readonly publicKeys: Readonly<Record<string, string>>;
  readonly payloadLabel?: string;
}): { readonly envelope: SignedAttestationEnvelope; readonly slots: readonly unknown[] } {
  const envelope = parseSignedEnvelope(input, shape);
  const payload = Buffer.from(envelope.payload, "base64url");
  verifyPinnedEd25519({
    keyId: envelope.keyId,
    payload,
    signature: Buffer.from(envelope.signature, "base64url"),
    publicKeys: shape.publicKeys,
    noun: shape.noun,
  });
  const slots = decodeSlotArray({
    payload,
    profile: shape.profile,
    slotCount: shape.slotCount,
    ...(shape.payloadLabel === undefined ? {} : { label: shape.payloadLabel }),
  });
  return { envelope, slots };
}
