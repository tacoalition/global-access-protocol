import assert from "node:assert/strict";
import test from "node:test";
import { buildBabyjub } from "circomlibjs";
import {
  TM_CIPHERTEXT_BYTES,
  createBabyJubTmCipher,
  decryptBabyJubTmCiphertext,
  hexToBytes,
  type TmEncryptionContext,
} from "../src/index";

test("Baby-Jubjub XChaCha20 profile round-trips and authenticates AAD", async () => {
  const babyJub = await buildBabyjub();
  const privateScalar = 123456789n;
  const publicPoint = babyJub.mulPointEscalar(babyJub.Base8, privateScalar);
  const publicKey = {
    x: BigInt(babyJub.F.toObject(publicPoint[0])),
    y: BigInt(babyJub.F.toObject(publicPoint[1])),
  };
  let counter = 0;
  const cipher = await createBabyJubTmCipher({
    monitorPublicKey: publicKey,
    randomBytes(length) {
      counter += 1;
      const bytes = new Uint8Array(length);
      bytes.fill(counter);
      return bytes;
    },
  });
  const context: TmEncryptionContext = {
    chainId: 84532n,
    sessionManager: 1n,
    account: 2n,
    policyId: 3n,
    policyVersion: 1n,
    validUntil: 4n,
    accountNonce: 5n,
    ordb: 6n,
    gatedContract: 7n,
    monitorKeyId: 8n,
    pseudonymCommitment: 9n,
    ikRefCommitment: 10n,
  };
  const plaintext = { pseudonym: 11n, blindingR: 12n, ita0: 13n, ikId0: 14n , ikBlind: 99n};
  const payload = hexToBytes(await cipher.encrypt(plaintext, context));
  // 1 version + 32+32 ephemeral point + 24 nonce + (160 plaintext + 16 tag) = 265.
  // Five field elements since ikRefCommitment gained a blinding factor; it was 233 with four.
  assert.equal(payload.length, 265);
  assert.equal(payload.length, TM_CIPHERTEXT_BYTES, "the exported constant must track the format");
  assert.deepEqual(
    await decryptBabyJubTmCiphertext(payload, privateScalar, context),
    plaintext,
  );
  await assert.rejects(
    decryptBabyJubTmCiphertext(payload, privateScalar, { ...context, accountNonce: 6n }),
  );
  payload[payload.length - 1] ^= 1;
  await assert.rejects(decryptBabyJubTmCiphertext(payload, privateScalar, context));
});

/**
 * TWO SEALINGS OF THE SAME SESSION MUST DIFFER: the gap that mutation testing found.
 *
 * A reviewer pinned the ephemeral scalar AND the nonce to constants and every test in this file
 * still passed. That is XChaCha20 keystream reuse: XOR two envelopes sealed under the same key and
 * nonce and the difference of the plaintexts falls out, which for this payload means the difference
 * of two pseudonyms. Catastrophic, and invisible to the suite.
 *
 * It was invisible because the tests above inject a DETERMINISTIC `randomBytes`, correctly, since
 * they assert an exact payload length and a round trip. So freshness needs its own test, on the real
 * random source, asserting the property that determinism hides.
 */
test("two sealings of the same session are different ciphertexts", async () => {
  const babyJub = await buildBabyjub();
  const privateScalar = 2n ** 200n + 7n;
  const point = babyJub.mulPointEscalar(babyJub.Base8, privateScalar);
  const monitorPublicKey = {
    x: BigInt(babyJub.F.toObject(point[0])),
    y: BigInt(babyJub.F.toObject(point[1])),
  };
  // NO randomBytes override: the real source, which is the thing under test.
  const cipher = await createBabyJubTmCipher({ monitorPublicKey });
  const context: TmEncryptionContext = {
    chainId: 84532n, sessionManager: 1n, account: 2n, policyId: 3n, policyVersion: 1n,
    validUntil: 4n, accountNonce: 5n, ordb: 6n, gatedContract: 7n, monitorKeyId: 8n,
    pseudonymCommitment: 9n, ikRefCommitment: 10n,
  };
  const plaintext = { pseudonym: 11n, blindingR: 12n, ita0: 13n, ikId0: 14n, ikBlind: 99n };

  const a = await cipher.encrypt(plaintext, context);
  const b = await cipher.encrypt(plaintext, context);
  assert.notEqual(a, b, "identical plaintext and context must still seal to different bytes");

  // And the nonces specifically, equal ciphertexts would fail above, but equal NONCES with
  // different ephemeral keys would not, and the nonce is half of what makes the keystream unique.
  const nonceOf = (hex: string) => hex.slice(2 + 2 * (1 + 64), 2 + 2 * (1 + 64 + 24));
  assert.notEqual(nonceOf(a), nonceOf(b), "the nonce must be fresh per sealing");

  // Both still open, so freshness is not bought by breaking the round trip.
  for (const sealed of [a, b]) {
    assert.deepEqual(
      await decryptBabyJubTmCiphertext(hexToBytes(sealed), privateScalar, context),
      plaintext,
    );
  }
});

/**
 * EVERY AAD FIELD IS LOAD-BEARING, asserted field by field.
 *
 * `tm-envelope.ts` promises that "a ciphertext lifted onto any other session fails to authenticate".
 * Mutation testing found five of the twelve fields could be dropped from the AAD with the suite
 * green, so the promise held for the fields that happened to be tested and nothing enforced the
 * rest. This walks all twelve.
 */
test("every field of the associated data is authenticated", async () => {
  const babyJub = await buildBabyjub();
  const privateScalar = 2n ** 200n + 11n;
  const point = babyJub.mulPointEscalar(babyJub.Base8, privateScalar);
  const cipher = await createBabyJubTmCipher({
    monitorPublicKey: {
      x: BigInt(babyJub.F.toObject(point[0])),
      y: BigInt(babyJub.F.toObject(point[1])),
    },
  });
  const context: TmEncryptionContext = {
    chainId: 84532n, sessionManager: 1n, account: 2n, policyId: 3n, policyVersion: 1n,
    validUntil: 4n, accountNonce: 5n, ordb: 6n, gatedContract: 7n, monitorKeyId: 8n,
    pseudonymCommitment: 9n, ikRefCommitment: 10n,
  };
  const plaintext = { pseudonym: 11n, blindingR: 12n, ita0: 13n, ikId0: 14n, ikBlind: 99n };
  const payload = hexToBytes(await cipher.encrypt(plaintext, context));

  const fields = Object.keys(context) as (keyof TmEncryptionContext)[];
  assert.equal(fields.length, 12, "if the context gains a field, it needs covering here too");

  for (const field of fields) {
    const lifted = { ...context, [field]: context[field] + 1n };
    await assert.rejects(
      decryptBabyJubTmCiphertext(payload, privateScalar, lifted),
      `an envelope must not open under a context whose ${field} differs`,
    );
  }
});
