// The prover and the transaction monitor must agree on ONE envelope. These tests pin that
// agreement at the layer both sides import, without a chain: build a context the way the prover
// does, build it again the way the monitor does, and require the same bytes and a clean
// round-trip through the real cipher.
import assert from "node:assert/strict";
import test from "node:test";
import { encodeAbiParameters } from "viem";
import {
  babyJubPublicKeyFromScalar,
  createBabyJubTmCipher,
  decodeSessionEnvelope,
  decryptBabyJubTmCiphertext,
  encodeTmAad,
  grantNonceCandidates,
  hexToBytes,
  monitorScalarMatchesKey,
  sessionEnvelopeCiphertextBytes,
  tmSessionContext,
  tmSessionContextForStoredSession,
  tmSessionContextForWitness,
  type TmEncryptionContext,
  type WitnessData,
} from "../src/index";

const MONITOR_SCALAR = 0x4d0f2a1b9c8e7d6a5b4c3d2e1f00998877665544332211aabbccddeeff001122n;
const OTHER_MONITOR_SCALAR = 0x1122334455667788990011223344556677889900aabbccddeeff001122334455n;

const SESSION_MANAGER = "0x00000000000000000000000000000000000000A1" as const;
const ACCOUNT = "0x00000000000000000000000000000000000000B2" as const;
const ORDB = "0x00000000000000000000000000000000000000C3" as const;
const SCOPE = "0x00000000000000000000000000000000000000D4" as const;
const POLICY_ID =
  "0x0000000000000000000000000000000000000000000000000000000000000123" as const;

const COMMITMENTS = { pseudonymCommitment: 777n, ikRefCommitment: 888n };
const PLAINTEXT = {
  pseudonym: 0x2b1cf00d0000000000000000000000000000000000000000000000000000001n,
  blindingR: 0x0d15ea5e0000000000000000000000000000000000000000000000000000002n,
  ita0: BigInt("0x00000000000000000000000000000000000000E5"),
  ikId0: 4242n, ikBlind: 99n,
};

/** The grant nonce: what the prover sealed under, one below the post-grant counter. */
const GRANT_NONCE = 6n;
const POST_GRANT_SESSION_NONCE = GRANT_NONCE + 1n;
const MONITOR_KEY_ID = 0x9a9an;
const VALID_UNTIL = 1_900_000_000n;
const POLICY_VERSION = 3n;

/** A witness shaped like the one the joined prover builds. Only the bound fields matter here. */
function witness(): WitnessData {
  return {
    chainId: 84532n,
    sessionManager: BigInt(SESSION_MANAGER),
    account: BigInt(ACCOUNT),
    policyId: BigInt(POLICY_ID),
    policyVersion: POLICY_VERSION,
    validUntil: VALID_UNTIL,
    accountNonce: GRANT_NONCE,
    ordbId: BigInt(ORDB),
    gatedContract: BigInt(SCOPE),
    monitorKeyId: MONITOR_KEY_ID,
  } as unknown as WitnessData;
}

/** What SessionManager `_install` writes: abi.encode(pub[16], pub[17], pub[18], ciphertext). */
function storedEnvelope(ciphertext: `0x${string}`): `0x${string}` {
  return encodeAbiParameters(
    [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes" }],
    [
      COMMITMENTS.pseudonymCommitment,
      COMMITMENTS.ikRefCommitment,
      MONITOR_KEY_ID,
      ciphertext,
    ],
  );
}

function storedSession(encryptedPseudonym: `0x${string}`) {
  return {
    policyId: POLICY_ID,
    policyVersion: POLICY_VERSION,
    validUntil: VALID_UNTIL,
    gatedContract: SCOPE,
    ordb: ORDB,
    encryptedPseudonym,
  };
}

/** Seal a pseudonym exactly as the prover does, then wrap it as the contract does. */
async function sealedSession(scalar = MONITOR_SCALAR) {
  const monitorPublicKey = await babyJubPublicKeyFromScalar(scalar);
  const cipher = await createBabyJubTmCipher({ monitorPublicKey });
  const proverContext = tmSessionContextForWitness(witness(), COMMITMENTS);
  const ciphertext = await cipher.encrypt(PLAINTEXT, proverContext);
  return { proverContext, session: storedSession(storedEnvelope(ciphertext)) };
}

/** The monitor's reconstruction of the same context, from chain reads only. */
function monitorSide(session: ReturnType<typeof storedSession>, nonce = POST_GRANT_SESSION_NONCE) {
  const candidate = grantNonceCandidates(nonce)[0];
  return tmSessionContextForStoredSession({
    chainId: 84532,
    sessionManager: SESSION_MANAGER,
    account: ACCOUNT,
    accountNonce: candidate,
    session,
  });
}

test("prover and monitor derive byte-identical associated data for one session", async () => {
  const { proverContext, session } = await sealedSession();
  const { context: monitorContext, envelope } = monitorSide(session);
  assert.deepEqual(monitorContext, proverContext);
  assert.deepEqual(
    Array.from(encodeTmAad(monitorContext)),
    Array.from(encodeTmAad(proverContext)),
  );
  // The monitor recovers the proven commitments from the envelope, not from the prover.
  assert.equal(envelope.pseudonymCommitment, COMMITMENTS.pseudonymCommitment);
  assert.equal(envelope.ikRefCommitment, COMMITMENTS.ikRefCommitment);
  assert.equal(envelope.monitorKeyId, MONITOR_KEY_ID);
});

test("a prover ciphertext decrypts to exactly the plaintext the monitor expects", async () => {
  const { session } = await sealedSession();
  const { context, envelope } = monitorSide(session);
  const opened = await decryptBabyJubTmCiphertext(
    sessionEnvelopeCiphertextBytes(envelope),
    MONITOR_SCALAR,
    context,
  );
  assert.deepEqual(opened, PLAINTEXT);
});

test("the sealed pseudonym is not readable in the stored envelope", async () => {
  const { session } = await sealedSession();
  // The whole point of the migration: the pseudonym must not appear in the bytes on chain.
  const stored = session.encryptedPseudonym.toLowerCase();
  assert.equal(stored.includes(PLAINTEXT.pseudonym.toString(16)), false);
  assert.equal(stored.includes(PLAINTEXT.blindingR.toString(16)), false);
});

test("a tampered ciphertext is refused", async () => {
  const { session } = await sealedSession();
  const { context, envelope } = monitorSide(session);
  const payload = sessionEnvelopeCiphertextBytes(envelope);
  payload[payload.length - 1] ^= 0x01;
  await assert.rejects(
    decryptBabyJubTmCiphertext(payload, MONITOR_SCALAR, context),
  );
});

test("a ciphertext addressed to a different monitor key is refused", async () => {
  const { session } = await sealedSession(OTHER_MONITOR_SCALAR);
  const { context, envelope } = monitorSide(session);
  await assert.rejects(
    decryptBabyJubTmCiphertext(
      sessionEnvelopeCiphertextBytes(envelope),
      MONITOR_SCALAR,
      context,
    ),
  );
  // And the monitor can tell it holds the wrong key before it ever tries.
  assert.equal(
    await monitorScalarMatchesKey(
      MONITOR_SCALAR,
      await babyJubPublicKeyFromScalar(OTHER_MONITOR_SCALAR),
    ),
    false,
  );
});

test("an envelope lifted onto a different session does not authenticate", async () => {
  const { session } = await sealedSession();
  const { envelope } = monitorSide(session);
  const payload = sessionEnvelopeCiphertextBytes(envelope);
  const base = monitorSide(session).context;
  const drifted: Array<[string, TmEncryptionContext]> = [
    ["account", tmSessionContext({ ...base, account: BigInt(SCOPE) })],
    ["validUntil", tmSessionContext({ ...base, validUntil: VALID_UNTIL + 1n })],
    ["gatedContract", tmSessionContext({ ...base, gatedContract: BigInt(ORDB) })],
    ["accountNonce", tmSessionContext({ ...base, accountNonce: GRANT_NONCE + 1n })],
    ["chainId", tmSessionContext({ ...base, chainId: 31337n })],
    ["policyVersion", tmSessionContext({ ...base, policyVersion: POLICY_VERSION + 1n })],
  ];
  for (const [label, context] of drifted) {
    await assert.rejects(
      decryptBabyJubTmCiphertext(payload, MONITOR_SCALAR, context),
      `${label} drift must not authenticate`,
    );
  }
});

test("the grant nonce is the counter as it stood before the grant", () => {
  assert.deepEqual(grantNonceCandidates(5n), [4n, 3n, 2n, 1n]);
  // Newest first, and never below zero for a fresh account's first grant.
  assert.deepEqual(grantNonceCandidates(1n), [0n]);
  assert.deepEqual(grantNonceCandidates(0n), []);
});

test("a foreign or legacy envelope is rejected rather than misread", () => {
  // The old cleartext envelope: four bare words, no outer wrapper.
  const legacy = `0x${"11".repeat(128)}` as const;
  assert.throws(() => decodeSessionEnvelope(legacy));
  assert.equal(hexToBytes(legacy).length, 128);
});

/**
 * THE IDENTITY KEEPER MUST NOT BE READABLE FROM pub[17].
 *
 * `ikRefCommitment` used to be `Poseidon(ita0, ikId0)` over two PUBLIC values, `ita0` is a contract
 * address and `ikId0` is emitted in the clear by `IKRegistered`, so it inverted by table lookup.
 * On a live chain that identified the keeper by name in 6 of 6 sessions, with no keys, against the
 * white paper's §5.2 ("without revealing this information to the general public").
 *
 * The blinding factor is what stops it, so this asserts the property the way an attacker would test
 * it: build the table from public data and look the commitment up in it.
 */
