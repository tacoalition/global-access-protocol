import assert from "node:assert/strict";
import { test } from "node:test";
import { ATTESTATION_PROFILE } from "../../gap-identity-keeper-v2/src/provider-attestation";
import {
  DEFAULT_DETERMINATION_FRESHNESS_SECONDS,
  SUITABILITY_PROFILE,
  verifySuitabilityAttestation,
} from "../src/suitability-attestation";
import {
  assertSuitabilityKeysAreDistinct,
  gatedSuitabilityAttributes,
  suitabilityGateConfigFromEnvironment,
} from "../src/suitability-gate";
import {
  FUND_IK_ID,
  SUBJECT_DID,
  SUITABILITY_KEY_ID,
  createSigningKey,
  signSuitability,
  suitabilityEnv,
  suitabilitySlots,
} from "./suitability-fixture";

const NOW = () => BigInt(Math.floor(Date.now() / 1000));

function context(key: ReturnType<typeof createSigningKey>, overrides: Record<string, unknown> = {}) {
  return {
    policy: {
      fundIkId: FUND_IK_ID,
      environment: "sandbox" as const,
      publicKeys: { [SUITABILITY_KEY_ID]: key.publicKeyHex },
    },
    expectedSubjectDid: SUBJECT_DID,
    now: NOW(),
    ...overrides,
  };
}

test("a fund-IK signed determination yields attrs[4..7] and a finite expiry", () => {
  const key = createSigningKey();
  const verified = verifySuitabilityAttestation(signSuitability(key), context(key));
  // regime 1 is [accredited, qualifiedPurchaser, evidenceTier, reserved]; NET_WORTH => tier 3.
  assert.deepEqual(verified.attributes, [1n, 1n, 3n, 0n]);
  assert.equal(verified.determination.fundIkId, FUND_IK_ID);
  assert.equal(verified.determination.subjectDid, SUBJECT_DID);
  assert.ok(verified.determination.expiresAt > NOW(), "the determination must carry a real expiry");
});

test("an unsigned, foreign-keyed, or tampered artifact never verifies", () => {
  const key = createSigningKey();
  const stranger = createSigningKey();
  assert.throws(() => verifySuitabilityAttestation(signSuitability(stranger), context(key)),
    /signature is invalid/);
  assert.throws(
    () => verifySuitabilityAttestation(signSuitability(key, suitabilitySlots(), "other-key"), context(key)),
    /is not pinned/,
  );
  // Swap the signed bytes for an upgraded determination, keeping the signature.
  const window = { reviewedAtSeconds: Number(NOW()) - 3600, expiresAtSeconds: Number(NOW()) + 86400 };
  const forged = {
    ...signSuitability(key, suitabilitySlots({ ...window, accredited: "0", qualifiedPurchaser: "0" })),
    payload: Buffer.from(
      JSON.stringify(suitabilitySlots({ ...window, accredited: "1", qualifiedPurchaser: "1" })),
      "utf8",
    ).toString("base64url"),
  };
  assert.throws(() => verifySuitabilityAttestation(forged, context(key)), /signature is invalid/);
  assert.throws(() => verifySuitabilityAttestation(undefined, context(key)),
    /suitability attestation must be an object/);
});

test("a KYC provider decision is not a suitability attestation", () => {
  const key = createSigningKey();
  // Same envelope, same signer, same 13 slots, only the profile tag and the
  // authority slot say "this is the KYC provider". Both refuse.
  assert.notEqual(SUITABILITY_PROFILE, ATTESTATION_PROFILE);
  assert.throws(
    () => verifySuitabilityAttestation(
      signSuitability(key, suitabilitySlots(), SUITABILITY_KEY_ID, ATTESTATION_PROFILE),
      context(key),
    ),
    /suitability attestation profile mismatch/,
  );
  assert.throws(
    () => verifySuitabilityAttestation(
      signSuitability(key, suitabilitySlots({ authority: "kyc-provider" })), context(key),
    ),
    /authority is not the fund IK/,
  );
});

test("the determination is bound to one DID, one fund IK, and one time window", () => {
  const key = createSigningKey();
  assert.throws(
    () => verifySuitabilityAttestation(signSuitability(key),
      context(key, { expectedSubjectDid: `0x${"9c".repeat(32)}` })),
    /about a different person DID/,
  );
  assert.throws(
    () => verifySuitabilityAttestation(signSuitability(key, suitabilitySlots({ fundIkId: "other-fund" })),
      context(key)),
    /not issued by the configured fund IK/,
  );
  const now = Number(NOW());
  assert.throws(
    () => verifySuitabilityAttestation(
      signSuitability(key, suitabilitySlots({
        reviewedAtSeconds: now - 7200, expiresAtSeconds: now - 60,
      })),
      context(key),
    ),
    /suitability determination has expired/,
  );
  const stale = now - Number(DEFAULT_DETERMINATION_FRESHNESS_SECONDS) - 3600;
  assert.throws(
    () => verifySuitabilityAttestation(
      signSuitability(key, suitabilitySlots({ reviewedAtSeconds: stale, expiresAtSeconds: now + 3600 })),
      context(key),
    ),
    /must be re-reviewed/,
  );
});

test("a qualified purchaser who is not accredited is refused", () => {
  const key = createSigningKey();
  assert.throws(
    () => verifySuitabilityAttestation(
      signSuitability(key, suitabilitySlots({ accredited: "0", qualifiedPurchaser: "1" })), context(key),
    ),
    /qualified purchaser determination requires accreditation/,
  );
  // A negative determination is still a determination: [0, 0] verifies.
  const negative = verifySuitabilityAttestation(
    signSuitability(key, suitabilitySlots({ accredited: "0", qualifiedPurchaser: "0" })), context(key),
  );
  assert.deepEqual(negative.attributes, [0n, 0n, 3n, 0n]);
});

test("an unconfigured suitability gate refuses rather than returning attributes", () => {
  assert.equal(suitabilityGateConfigFromEnvironment({}), undefined);
  assert.throws(
    () => gatedSuitabilityAttributes({ did: SUBJECT_DID, env: {} }),
    /requires a fund-IK suitability attestation/,
  );
});

test("the suitability signer may not be the KYC provider's signer", () => {
  const key = createSigningKey();
  const env = suitabilityEnv({ key, envelope: signSuitability(key) });
  // Same key material pinned on both sides.
  assert.throws(
    () => suitabilityGateConfigFromEnvironment({
      ...env,
      GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON: JSON.stringify({ "kyc-key-1": key.publicKeyHex }),
    }),
    /must never be sufficient to mint accredited\/QP/,
  );
  // Same keyId reused across the two pin sets.
  assert.throws(
    () => assertSuitabilityKeysAreDistinct(
      { [SUITABILITY_KEY_ID]: key.publicKeyHex },
      { GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON: JSON.stringify({ [SUITABILITY_KEY_ID]: `0x${"11".repeat(32)}` }) },
    ),
    /also pinned as a KYC provider key/,
  );
  // Genuinely distinct authorities configure cleanly.
  const provider = createSigningKey();
  const config = suitabilityGateConfigFromEnvironment({
    ...env,
    GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON: JSON.stringify({ "kyc-key-1": provider.publicKeyHex }),
  });
  assert.equal(config?.policy.fundIkId, FUND_IK_ID);
});

test("the gate refuses two sources for the one artifact", () => {
  const key = createSigningKey();
  assert.throws(
    () => suitabilityGateConfigFromEnvironment({
      ...suitabilityEnv({ key, envelope: signSuitability(key) }),
      GAP_FUND_IK_SUITABILITY_ATTESTATION_PATH: "/tmp/nope.json",
    }),
    /never both/,
  );
  assert.throws(
    () => suitabilityGateConfigFromEnvironment({
      GAP_FUND_IK_SUITABILITY_KEYS_JSON: JSON.stringify({ [SUITABILITY_KEY_ID]: key.publicKeyHex }),
      GAP_FUND_IK_ID: FUND_IK_ID,
    }),
    /is required once the suitability gate is configured/,
  );
});
