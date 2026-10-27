import assert from "node:assert/strict";
import { test } from "node:test";
import { assertIdentityCredentialMintAllowed, type IdentityMintRequest } from "../src/mint-guard";
import { identityGateIsConfigured } from "../src/identity-gate";
import {
  SUBJECT_DID, createSigningKey, signSuitability, suitabilityEnv, suitabilitySlots,
} from "./suitability-fixture";

/**
 * THE GUARD, AS THE LIGHT STACK SEES IT.
 *
 * The full stack tests this against a live Identity Keeper. This build runs no services, so what is
 * testable here is the part that matters most for a reference implementation: the refusals. A
 * credential may not be minted from a KYC decision alone, an ARMED provider gate may not be served by
 * a local approximation, and no operator flag reopens either door.
 *
 * Attribute order under GAP_ATTR_CRED_V3:
 *   attrs[0..3] residency, sanctions, citizenship, reserved: the KYC provider's
 *   attrs[4..7] accredited, qualifiedPurchaser, evidenceTier, reserved: the fund IK's
 */
const DID = SUBJECT_DID;
const TRUTHFUL: IdentityMintRequest["attributes"] = [840n, 0n, 840n, 0n, 1n, 1n, 3n, 0n];

function request(over: Partial<IdentityMintRequest> = {}): IdentityMintRequest {
  return {
    chainId: 31337,
    did: DID,
    attributes: TRUTHFUL,
    leaf: "investor",
    warn: () => {},
    env: {},
    ...over,
  };
}

/** The four variables that arm a provider gate in the real Identity Keeper. */
const ARMED_PROVIDER_GATE = {
  GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON: '{"k":"0x00"}',
  GAP_IK_PROVIDER_CLIENT_ID: "client",
  GAP_IK_PROVIDER_LEVEL_NAME: "level",
  GAP_IK_PROVIDER_REVIEWED_CONFIG_SHA256: `0x${"11".repeat(32)}`,
} as const;

test("a bare checkout refuses, and names BOTH authorities", async () => {
  await assert.rejects(
    assertIdentityCredentialMintAllowed(request()),
    /verified provider decision \(attrs\[0\.\.3\]\)/,
  );
  await assert.rejects(
    assertIdentityCredentialMintAllowed(request()),
    /fund-IK suitability attestation \(attrs\[4\.\.7\]\)/,
  );
});

test("an ARMED provider gate is never served by this build, and no flag reopens it", async () => {
  const key = createSigningKey();
  const env = {
    ...suitabilityEnv({ key, envelope: signSuitability(key, suitabilitySlots({ subjectDid: DID })) }),
    ...ARMED_PROVIDER_GATE,
  };
  assert.equal(identityGateIsConfigured(env), true, "the fixture must actually arm the gate");
  await assert.rejects(
    assertIdentityCredentialMintAllowed(request({ env })),
    /requires the Identity Keeper service, which this build does not run/,
  );
  // The local-fixtures acknowledgement is for an UNARMED gate. It must not stand in for an armed one.
  await assert.rejects(
    assertIdentityCredentialMintAllowed(
      request({ env: { ...env, GAP_ALLOW_INSECURE_LOCAL_FIXTURES: "1" } }),
    ),
    /requires the Identity Keeper service, which this build does not run/,
  );
});

test("the suitability half is authoritative over attrs[4..7]", async () => {
  const key = createSigningKey();
  // The fund IK determined accredited but NOT a qualified purchaser.
  const env = suitabilityEnv({
    key,
    envelope: signSuitability(key, suitabilitySlots({
      subjectDid: DID, accredited: "1", qualifiedPurchaser: "0",
    })),
  });
  await assert.rejects(
    assertIdentityCredentialMintAllowed(request({ env })),
    /does not attest the accredited\/qualified-purchaser attributes/,
  );
  // The evidence TIER is equally binding: the fixture's basis is NET_WORTH, so tier 3 and no other.
  await assert.rejects(
    assertIdentityCredentialMintAllowed(request({
      env, attributes: [840n, 0n, 840n, 0n, 1n, 0n, 5n, 0n],
    })),
    /does not attest the accredited\/qualified-purchaser attributes/,
  );
});

test("with the gate unarmed, the local demo credential is allowed only on an explicit acknowledgement", async () => {
  const key = createSigningKey();
  const env = suitabilityEnv({
    key,
    envelope: signSuitability(key, suitabilitySlots({
      subjectDid: DID, accredited: "1", qualifiedPurchaser: "1",
    })),
  });
  assert.equal(identityGateIsConfigured(env), false);
  await assert.rejects(
    assertIdentityCredentialMintAllowed(request({ env })),
    /verified provider decision \(attrs\[0\.\.3\]\)/,
  );
  const warnings: string[] = [];
  const allowed = await assertIdentityCredentialMintAllowed(request({
    env: { ...env, GAP_ALLOW_INSECURE_LOCAL_FIXTURES: "1" },
    warn: (message) => warnings.push(message),
  }));
  // NOT fully attested: the suitability half is real, the identity half is a local fixture.
  assert.equal(allowed.attested, false);
  assert.ok(allowed.suitabilityExpiresAt !== undefined, "the real half still carries its expiry");
  assert.ok(warnings.length > 0, "an unattested local credential must warn, loudly");
});
