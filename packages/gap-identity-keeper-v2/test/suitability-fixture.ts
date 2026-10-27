// A stand-in fund IK that signs suitability attestations, plus the environment
// shapes the gate reads. Mirrors services/gap-ik-api/test/identity-gate-fixture,
// deliberately: the two attestations are verified by the same primitives, so
// their fixtures should be recognisably the same artifact.
import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { SUITABILITY_PROFILE } from "../src/suitability-attestation";

export const FUND_IK_ID = "gap-fund-ik-local";
export const SUITABILITY_KEY_ID = "gap-fund-ik-suitability-1";
export const REVIEWER_ID = "fund-ops.desk-1";
export const EVIDENCE_DIGEST = `0x${"7a".repeat(32)}`;
export const SUBJECT_DID = `0x${"3b".repeat(32)}` as `0x${string}`;

export interface SigningKey {
  readonly privateKey: KeyObject;
  readonly publicKeyHex: `0x${string}`;
}

export function createSigningKey(): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return { privateKey, publicKeyHex: `0x${Buffer.from(jwk.x, "base64url").toString("hex")}` };
}

function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

export interface SuitabilityOverrides {
  readonly authority?: unknown;
  readonly fundIkId?: string;
  readonly subjectDid?: string;
  readonly revision?: string;
  readonly accredited?: string;
  readonly qualifiedPurchaser?: string;
  readonly evidenceTier?: string;
  readonly reviewedAtSeconds?: number;
  readonly expiresAtSeconds?: number;
}

/** The normative 14-slot positional payload; order is load-bearing. */
export function suitabilitySlots(overrides: SuitabilityOverrides = {}): readonly unknown[] {
  const now = Math.floor(Date.now() / 1000);
  return [
    SUITABILITY_PROFILE,
    overrides.authority ?? "fund-ik",
    "sandbox",
    overrides.fundIkId ?? FUND_IK_ID,
    overrides.subjectDid ?? SUBJECT_DID,
    overrides.revision ?? "1",
    REVIEWER_ID,
    EVIDENCE_DIGEST,
    "NET_WORTH",
    overrides.accredited ?? "1",
    overrides.qualifiedPurchaser ?? "1",
    // NET_WORTH above => reviewed tier 3. The IK refuses a tier that is not the table's.
    overrides.evidenceTier ?? "3",
    iso(overrides.reviewedAtSeconds ?? now - 3600),
    String(overrides.expiresAtSeconds ?? now + 30 * 24 * 3600),
  ];
}

export interface Envelope {
  readonly profile: string;
  readonly keyId: string;
  readonly payload: string;
  readonly signature: string;
}

export function signSuitability(
  key: SigningKey,
  slots: readonly unknown[] = suitabilitySlots(),
  keyId = SUITABILITY_KEY_ID,
  profile = SUITABILITY_PROFILE,
): Envelope {
  const payload = Buffer.from(JSON.stringify(slots), "utf8");
  return {
    profile,
    keyId,
    payload: payload.toString("base64url"),
    signature: edSign(null, payload, key.privateKey).toString("base64url"),
  };
}

/** A minimal environment with ONLY the suitability gate armed. */
export function suitabilityEnv(input: {
  readonly key: SigningKey;
  readonly envelope: Envelope;
  readonly keyId?: string;
}): NodeJS.ProcessEnv {
  return {
    GAP_FUND_IK_SUITABILITY_KEYS_JSON: JSON.stringify({
      [input.keyId ?? SUITABILITY_KEY_ID]: input.key.publicKeyHex,
    }),
    GAP_FUND_IK_ID: FUND_IK_ID,
    GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON: JSON.stringify(input.envelope),
  };
}
