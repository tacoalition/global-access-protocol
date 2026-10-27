// The monitor's decision, with no chain in it.
//
// `reviewStoredSession` is the half of a grant the holder's wallet cannot do: open the sealed
// envelope, confirm it reopens the commitments the proof already committed to, and only then let
// the caller attest. Every refusal below was previously unreachable, because the CLI inlined this
// logic inside the same function that submitted the grant: there was no way to hand the monitor a
// forged envelope without also forging a proof.
//
// The commitments here are REAL Poseidon hashes of the plaintext, so the happy path is genuine
// arithmetic rather than two matching constants.
import assert from "node:assert/strict";
import test from "node:test";
import { encodeAbiParameters } from "viem";
import {
  babyJubPublicKeyFromScalar,
  createBabyJubTmCipher,
  decodeSessionEnvelope,
  reviewStoredSession,
  tmSessionContextForWitness,
  type WitnessData,
} from "../src/index";
import { realPoseidon } from "./wf-poseidon";

const MONITOR_SCALAR = 0x4d0f2a1b9c8e7d6a5b4c3d2e1f00998877665544332211aabbccddeeff001122n;
const FOREIGN_SCALAR = 0x1122334455667788990011223344556677889900aabbccddeeff001122334455n;

const SESSION_MANAGER = "0x00000000000000000000000000000000000000A1" as const;
const ACCOUNT = "0x00000000000000000000000000000000000000B2" as const;
const OTHER_ACCOUNT = "0x00000000000000000000000000000000000000BB" as const;
const ORDB = "0x00000000000000000000000000000000000000C3" as const;
const SCOPE = "0x00000000000000000000000000000000000000D4" as const;
const POLICY_ID = "0x0000000000000000000000000000000000000000000000000000000000000123" as const;

const PLAINTEXT = {
  pseudonym: 0x2b1cf00d0000000000000000000000000000000000000000000000000000001n,
  blindingR: 0x0d15ea5e0000000000000000000000000000000000000000000000000000002n,
  ita0: BigInt("0x00000000000000000000000000000000000000E5"),
  ikId0: 4242n,
  ikBlind: 99n,
};

const CHAIN_ID = 84532n;
const GRANT_NONCE = 6n;              // what the prover sealed under
const POST_GRANT_NONCE = GRANT_NONCE + 1n; // `_install` has already incremented it
const MONITOR_KEY_ID = 0x9a9an;
const VALID_UNTIL = 1_900_000_000n;
const POLICY_VERSION = 3n;

// Built once, lazily: esbuild emits CJS here, which has no top-level await.
let cached: { hash: Awaited<ReturnType<typeof realPoseidon>>; commitments: Commitments } | undefined;
interface Commitments { pseudonymCommitment: bigint; ikRefCommitment: bigint }

async function crypto() {
  if (!cached) {
    const hash = await realPoseidon();
    cached = {
      hash,
      commitments: {
        pseudonymCommitment: await hash.h2(PLAINTEXT.pseudonym, PLAINTEXT.blindingR),
        ikRefCommitment: await hash.h3(PLAINTEXT.ita0, PLAINTEXT.ikId0, PLAINTEXT.ikBlind),
      },
    };
  }
  return cached;
}

function witness(accountNonce = GRANT_NONCE): WitnessData {
  return {
    chainId: CHAIN_ID,
    sessionManager: BigInt(SESSION_MANAGER),
    account: BigInt(ACCOUNT),
    policyId: BigInt(POLICY_ID),
    policyVersion: POLICY_VERSION,
    validUntil: VALID_UNTIL,
    accountNonce,
    ordbId: BigInt(ORDB),
    gatedContract: BigInt(SCOPE),
    monitorKeyId: MONITOR_KEY_ID,
  } as unknown as WitnessData;
}

/** Exactly what `SessionManager._install` writes: the CONTRACT chooses the first three fields. */
function storedSession(ciphertext: `0x${string}`, commitments: Commitments) {
  return {
    policyId: POLICY_ID,
    policyVersion: POLICY_VERSION,
    validUntil: VALID_UNTIL,
    gatedContract: SCOPE,
    ordb: ORDB,
    encryptedPseudonym: encodeAbiParameters(
      [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes" }],
      [commitments.pseudonymCommitment, commitments.ikRefCommitment, MONITOR_KEY_ID, ciphertext],
    ),
  };
}

/** Seal as the prover does, then wrap as the contract does. */
async function sealed(opts: {
  scalar?: bigint;
  commitments?: Commitments;
  nonce?: bigint;
} = {}) {
  const commitments = opts.commitments ?? (await crypto()).commitments;
  const monitorPublicKey = await babyJubPublicKeyFromScalar(opts.scalar ?? MONITOR_SCALAR);
  const cipher = await createBabyJubTmCipher({ monitorPublicKey });
  const ciphertext = await cipher.encrypt(
    PLAINTEXT,
    tmSessionContextForWitness(witness(opts.nonce ?? GRANT_NONCE), commitments),
  );
  return storedSession(ciphertext, commitments);
}

async function review(
  session: ReturnType<typeof storedSession>,
  over: Record<string, unknown> = {},
) {
  return reviewStoredSession({
    chainId: CHAIN_ID,
    sessionManager: SESSION_MANAGER,
    account: ACCOUNT,
    sessionNonce: POST_GRANT_NONCE,
    session,
    monitorScalar: MONITOR_SCALAR,
    hash: (await crypto()).hash,
    ...over,
  });
}

test("a well-formed session opens and reopens both proven commitments", async () => {
  const result = await review(await sealed());
  assert.deepEqual(result.opened, PLAINTEXT);
  assert.equal(result.accountNonce, GRANT_NONCE, "the grant nonce is one below the counter");
  assert.equal(result.envelope.pseudonymCommitment, (await crypto()).commitments.pseudonymCommitment);
  assert.equal(result.envelope.monitorKeyId, MONITOR_KEY_ID);
});

test("a monitor holding the wrong key cannot open it", async () => {
  await assert.rejects(
    review(await sealed(), { monitorScalar: FOREIGN_SCALAR }),
    /does not open under this monitor key/,
  );
});

test("a session sealed to a different monitor is refused", async () => {
  await assert.rejects(review(await sealed({ scalar: FOREIGN_SCALAR })), /does not open/);
});

test("a tampered ciphertext is refused by the AEAD tag", async () => {
  const { commitments } = await crypto();
  // Decode, flip one hex digit in the MIDDLE of the sealed payload, re-wrap with the envelope's
  // declared fields untouched. Mutating the outer bytes instead is not a test: the first attempt
  // here flipped a digit inside the ABI padding of the `bytes` field, which the decoder discards,
  // and the session opened cleanly.
  const { ciphertext } = decodeSessionEnvelope((await sealed()).encryptedPseudonym);
  const mid = 2 + Math.floor((ciphertext.length - 2) / 2);
  const flipped = (ciphertext.slice(0, mid)
    + (ciphertext[mid] === "a" ? "b" : "a")
    + ciphertext.slice(mid + 1)) as `0x${string}`;
  assert.notEqual(flipped, ciphertext, "the flip must actually change the payload");
  await assert.rejects(review(storedSession(flipped, commitments)), /does not open/);
});

test("a monitor reading the wrong account authenticates nothing", async () => {
  // The account is part of the associated data, so reviewing one holder's envelope as another's
  // fails the tag rather than opening to something plausible.
  await assert.rejects(review(await sealed(), { account: OTHER_ACCOUNT }), /does not open/);
});

test("a holder who seals a pseudonym other than the one they proved is refused", async () => {
  // THE ATTACK THIS CHECK EXISTS FOR. The envelope's commitments come from the contract, so they
  // are the proven ones; the holder controls only what they SEAL. Declaring a commitment the
  // plaintext does not reopen still authenticates: it is in the associated data, and is caught
  // only by recomputing the hash.
  const { commitments } = await crypto();
  const session = await sealed({
    commitments: {
      pseudonymCommitment: commitments.pseudonymCommitment + 1n,
      ikRefCommitment: commitments.ikRefCommitment,
    },
  });
  await assert.rejects(review(session), /does not reopen the proven commitment pub\[16\]/);
});

test("a spoofed identity-keeper reference is refused", async () => {
  const { commitments } = await crypto();
  const session = await sealed({
    commitments: {
      pseudonymCommitment: commitments.pseudonymCommitment,
      ikRefCommitment: commitments.ikRefCommitment + 1n,
    },
  });
  await assert.rejects(review(session), /does not reopen the proven commitment pub\[17\]/);
});

test("a grant that raced the monitor's reads still opens, within the lookback", async () => {
  // Two further grants landed on the account before the monitor looked, so the counter has moved
  // past the value the prover sealed under. Liveness, not relaxation: the tag still decides.
  const result = await review(await sealed(), { sessionNonce: GRANT_NONCE + 3n });
  assert.equal(result.accountNonce, GRANT_NONCE);
});

test("beyond the lookback it refuses rather than searching forever", async () => {
  await assert.rejects(
    review(await sealed(), { sessionNonce: GRANT_NONCE + 20n }),
    /tried 4 grant nonces/,
  );
});

test("a session proven against a since-rotated monitor key is refused", async () => {
  // The envelope still OPENS: the AEAD key is derived from the id inside it, so a monitor holding
  // the old scalar sees nothing wrong. Only comparing against the ORDB's live id catches it.
  await assert.rejects(
    review(await sealed(), { expectedMonitorKeyId: MONITOR_KEY_ID + 1n }),
    /was proven against monitor key/,
  );
});

test("the live monitor key id matching the envelope is accepted", async () => {
  const result = await review(await sealed(), { expectedMonitorKeyId: MONITOR_KEY_ID });
  assert.equal(result.envelope.monitorKeyId, MONITOR_KEY_ID);
});

test("an account that was never granted a session has nothing to attest", async () => {
  await assert.rejects(review(await sealed(), { sessionNonce: 0n }), /never been granted/);
});
