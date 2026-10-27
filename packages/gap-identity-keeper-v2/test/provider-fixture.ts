import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { COUNTRY_TABLE_REVISION } from "../src/country-table";
import { ATTESTATION_PROFILE, type AttestationPolicy, type ProviderAttestationEnvelope } from "../src/provider-attestation";
import type { LiveProviderStatus, StoredProviderDecision } from "../src/provider-decision-port";

export const NOW = 1_800_000_000n;
export const KEY_ID = "provider-key-1";
export const CLIENT_ID = "dsi-demo-client";
export const LEVEL_NAME = "dsi-base-rwa-demo-v1";
export const REVIEWED_CONFIG = `0x${"ab".repeat(32)}` as const;
export const APPLICANT_ID = "applicant-0001";
export const NONCE = `0x${"cd".repeat(32)}` as const;

/** Two distinct canonical UUIDv4 customer-link ids (one per person). */
export const LINK_A = "123e4567-e89b-42d3-a456-426614174000";
export const LINK_B = "8f14e45f-ceea-467a-9b17-2c1b0f4e9d21";

export const PERSON_DID_KEY = new Uint8Array(32).fill(7);

export interface ProviderKey {
  readonly privateKey: KeyObject;
  readonly publicKeyHex: `0x${string}`;
}

export function createProviderKey(): ProviderKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return { privateKey, publicKeyHex: `0x${Buffer.from(jwk.x, "base64url").toString("hex")}` };
}

export function policyFor(key: ProviderKey): AttestationPolicy {
  return {
    clientId: CLIENT_ID,
    levelName: LEVEL_NAME,
    environment: "sandbox",
    levelPolicyRevision: 1,
    reviewedConfigurationSha256: REVIEWED_CONFIG,
    countryTableRevision: COUNTRY_TABLE_REVISION,
    publicKeys: { [KEY_ID]: key.publicKeyHex },
  };
}

function iso(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toISOString();
}

export interface SlotOverrides {
  readonly subject?: string;
  readonly applicantId?: string;
  readonly decisionRevision?: string;
  readonly reviewAnswer?: "GREEN" | "RED";
  readonly reviewRejectType?: "FINAL" | "RETRY" | null;
  readonly country?: string;
  /** Citizenship is a SEPARATE slot from residency; both go through the reviewed table. */
  readonly citizenship?: string;
  readonly countryTableRevision?: string;
  readonly screeningResult?: "CLEAR" | "HIT";
  readonly screenedAt?: string;
  readonly observedAt?: string;
  readonly expiresAt?: string;
  readonly nonce?: string;
}

export function decisionSlots(overrides: SlotOverrides = {}): readonly unknown[] {
  const answer = overrides.reviewAnswer ?? "GREEN";
  return [
    ATTESTATION_PROFILE,
    "kyc-provider",
    "sandbox",
    CLIENT_ID,
    LEVEL_NAME,
    "1",
    REVIEWED_CONFIG,
    overrides.subject ?? LINK_A,
    overrides.applicantId ?? APPLICANT_ID,
    overrides.decisionRevision ?? "1",
    answer,
    overrides.reviewRejectType !== undefined
      ? overrides.reviewRejectType
      : (answer === "GREEN" ? null : "FINAL"),
    overrides.country ?? "GBR",
    overrides.citizenship ?? overrides.country ?? "GBR",
    overrides.countryTableRevision ?? String(COUNTRY_TABLE_REVISION),
    overrides.screeningResult ?? "CLEAR",
    overrides.screenedAt ?? iso(NOW - 600n),
    overrides.observedAt ?? iso(NOW - 300n),
    overrides.expiresAt ?? String(NOW + 3600n),
    overrides.nonce ?? NONCE,
  ];
}

export function signAttestation(
  key: ProviderKey,
  slots: readonly unknown[],
  keyId = KEY_ID,
): ProviderAttestationEnvelope {
  const payload = Buffer.from(JSON.stringify(slots), "utf8");
  return {
    profile: ATTESTATION_PROFILE,
    keyId,
    payload: payload.toString("base64url"),
    signature: edSign(null, payload, key.privateKey).toString("base64url"),
  };
}

export const APPROVED_STATUS = {
  reviewStatus: "completed",
  reviewResult: { reviewAnswer: "GREEN" as const },
};

export function storedFrom(envelope: ProviderAttestationEnvelope, nonce: string = NONCE): StoredProviderDecision {
  return {
    keyId: envelope.keyId,
    payload: envelope.payload,
    signature: envelope.signature,
    webhookEventId: nonce,
    webhookStatus: APPROVED_STATUS,
  };
}

export function liveFrom(
  envelope: ProviderAttestationEnvelope | undefined,
  overrides: Partial<LiveProviderStatus> = {},
): LiveProviderStatus {
  return {
    applicantId: APPLICANT_ID,
    externalUserId: LINK_A,
    ...APPROVED_STATUS,
    ...(envelope ? { providerAttestation: envelope } : {}),
    ...overrides,
  };
}
