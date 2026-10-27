import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { buildBabyjub } from "circomlibjs";
import type {
  TmCipher,
  TmEncryptionContext,
  TmEncryptionPlaintext,
} from "./types";
import {
  bigIntToBytes,
  bytesToBigInt,
  bytesToHex,
  concatBytes,
  type RandomBytes,
  secureRandomBytes,
} from "./random";
import { P } from "./types";

const PROFILE = new TextEncoder().encode("DSI_GAP_V2_TM_ENC_V1");
const DOMAIN = sha256(PROFILE);
const VERSION = 1;
const PAYLOAD_LENGTH = 1 + 32 + 32 + 24 + 160 + 16;   // 160 = five field elements

/** Version byte + ephemeral point + XChaCha nonce + sealed 128-byte plaintext + AEAD tag. */
export const TM_CIPHERTEXT_BYTES = PAYLOAD_LENGTH;

/**
 * Shape check for an envelope this process cannot open.
 *
 * The PROOF does not bind the ciphertext: that is what `ciphertextDigest` in the EIP-712
 * authorization is for, so a relayer forwarding an envelope it did not seal has no
 * cryptographic hold on it at all. It can still refuse one that is not even the right
 * SIZE, which is the difference between "the monitor will fail to attest and the holder is
 * left with a burned nonce and an unusable session" and "this was refused before it cost
 * anything". Says nothing about whether the contents decrypt; only the monitor can know that.
 */
export function assertTmCiphertextShape(ciphertext: string, label = "session ciphertext"): void {
  if (!/^0x[0-9a-fA-F]*$/.test(ciphertext)) {
    throw new Error(`GAP TM cipher: ${label} must be hex`);
  }
  const bytes = (ciphertext.length - 2) / 2;
  if (bytes !== PAYLOAD_LENGTH) {
    throw new Error(
      `GAP TM cipher: ${label} must be ${PAYLOAD_LENGTH} bytes, got ${bytes}`,
    );
  }
  if (ciphertext.slice(2, 4) !== "01") {
    throw new Error(`GAP TM cipher: ${label} is not a version-${VERSION} envelope`);
  }
}

export interface BabyJubPublicKey {
  x: bigint;
  y: bigint;
}

export interface BabyJubCipherOptions {
  monitorPublicKey: BabyJubPublicKey;
  randomBytes?: RandomBytes;
}

function word(value: bigint, label: string): Uint8Array {
  if (value < 0n || value >= 1n << 256n) {
    throw new Error(`GAP TM cipher: ${label} is not uint256`);
  }
  return bigIntToBytes(value);
}

function assertPlaintext(value: TmEncryptionPlaintext): void {
  for (const [label, field] of [
    ["pseudonym", value.pseudonym],
    ["blindingR", value.blindingR],
    ["ikId0", value.ikId0],
  ] as const) {
    if (field <= 0n || field >= P) throw new Error(`GAP TM cipher: invalid ${label}`);
  }
  if (value.ita0 <= 0n || value.ita0 >= 1n << 160n) {
    throw new Error("GAP TM cipher: invalid ita0 address");
  }
}

export function encodeTmPlaintext(value: TmEncryptionPlaintext): Uint8Array {
  assertPlaintext(value);
  return concatBytes(
    word(value.pseudonym, "pseudonym"),
    word(value.blindingR, "blindingR"),
    word(value.ita0, "ita0"),
    word(value.ikId0, "ikId0"),
    // Fifth field: the blinding factor for ikRefCommitment. Without it the monitor cannot reopen
    // pub[17], and WITH it published the keeper would be identifiable by anyone, which is exactly
    // what this replaced.
    word(value.ikBlind, "ikBlind"),
  );
}

export function decodeTmPlaintext(bytes: Uint8Array): TmEncryptionPlaintext {
  if (bytes.length !== 160) throw new Error("GAP TM cipher: plaintext must be 160 bytes");
  return {
    pseudonym: bytesToBigInt(bytes.subarray(0, 32)),
    blindingR: bytesToBigInt(bytes.subarray(32, 64)),
    ita0: bytesToBigInt(bytes.subarray(64, 96)),
    ikId0: bytesToBigInt(bytes.subarray(96, 128)),
    ikBlind: bytesToBigInt(bytes.subarray(128, 160)),
  };
}

export function encodeTmAad(context: TmEncryptionContext): Uint8Array {
  return concatBytes(
    DOMAIN,
    word(context.chainId, "chainId"),
    word(context.sessionManager, "sessionManager"),
    word(context.account, "account"),
    word(context.policyId, "policyId"),
    word(context.policyVersion, "policyVersion"),
    word(context.validUntil, "validUntil"),
    word(context.accountNonce, "accountNonce"),
    word(context.ordb, "ordb"),
    word(context.gatedContract, "gatedContract"),
    word(context.monitorKeyId, "monitorKeyId"),
    word(context.pseudonymCommitment, "pseudonymCommitment"),
    word(context.ikRefCommitment, "ikRefCommitment"),
  );
}

function sampleScalar(order: bigint, randomBytes: RandomBytes): bigint {
  const range = 1n << 256n;
  const limit = range - (range % order);
  for (;;) {
    const bytes = randomBytes(32);
    if (bytes.length !== 32) throw new Error("GAP TM cipher: random source returned the wrong byte length");
    const candidate = bytesToBigInt(bytes);
    if (candidate >= limit) continue;
    const scalar = candidate % order;
    if (scalar !== 0n) return scalar;
  }
}

// circomlibjs uses its own field representation internally.
function toPoint(babyJub: any, publicKey: BabyJubPublicKey): any {
  if (
    publicKey.x < 0n ||
    publicKey.x >= P ||
    publicKey.y < 0n ||
    publicKey.y >= P
  ) {
    throw new Error("GAP TM cipher: public key coordinate out of range");
  }
  const point = [babyJub.F.e(publicKey.x), babyJub.F.e(publicKey.y)];
  const identity = babyJub.F.isZero(point[0]) && babyJub.F.eq(point[1], babyJub.F.one);
  if (identity || !babyJub.inCurve(point) || !babyJub.inSubgroup(point)) {
    throw new Error("GAP TM cipher: invalid Baby-Jubjub public key");
  }
  return point;
}

function pointBytes(babyJub: any, point: any): Uint8Array {
  return concatBytes(
    bigIntToBytes(BigInt(babyJub.F.toObject(point[0]))),
    bigIntToBytes(BigInt(babyJub.F.toObject(point[1]))),
  );
}

function deriveKey(sharedPoint: Uint8Array, monitorKeyId: bigint): Uint8Array {
  return hkdf(
    sha256,
    sharedPoint,
    new Uint8Array(32),
    concatBytes(PROFILE, word(monitorKeyId, "monitorKeyId")),
    32,
  );
}

export async function createBabyJubTmCipher(options: BabyJubCipherOptions): Promise<TmCipher> {
  const babyJub = await buildBabyjub();
  const monitorPoint = toPoint(babyJub, options.monitorPublicKey);
  const randomBytes = options.randomBytes ?? secureRandomBytes;
  return {
    async encrypt(plaintext, context) {
      const scalar = sampleScalar(BigInt(babyJub.subOrder), randomBytes);
      const ephemeralPoint = babyJub.mulPointEscalar(babyJub.Base8, scalar);
      const sharedPoint = babyJub.mulPointEscalar(monitorPoint, scalar);
      const nonce = randomBytes(24);
      if (nonce.length !== 24) throw new Error("GAP TM cipher: random source returned the wrong nonce length");
      const key = deriveKey(pointBytes(babyJub, sharedPoint), context.monitorKeyId);
      const sealed = xchacha20poly1305(key, nonce, encodeTmAad(context)).encrypt(
        encodeTmPlaintext(plaintext),
      );
      // 160 plaintext + 16 AEAD tag. Five field elements now, not four: the fifth is ikBlind.
      if (sealed.length !== 176) throw new Error("GAP TM cipher: unexpected AEAD output");
      return bytesToHex(
        concatBytes(
          Uint8Array.of(VERSION),
          pointBytes(babyJub, ephemeralPoint),
          nonce,
          sealed,
        ),
      );
    },
  };
}

/**
 * The Baby-Jubjub public key a monitor private scalar addresses.
 *
 * The deployment publishes this point on the ORDB (`getMonitorKey`) and provers encrypt to it;
 * the monitor derives it from its configured scalar so a key that does not match the one the
 * chain declares is caught as configuration drift instead of as an unexplained decrypt failure.
 * Takes and returns only public values: the scalar never leaves this call.
 */
export async function babyJubPublicKeyFromScalar(
  privateScalar: bigint,
): Promise<BabyJubPublicKey> {
  const babyJub = await buildBabyjub();
  const scalar = privateScalar % BigInt(babyJub.subOrder);
  if (privateScalar <= 0n || scalar === 0n) {
    throw new Error("GAP TM cipher: invalid private scalar");
  }
  const point = babyJub.mulPointEscalar(babyJub.Base8, scalar);
  return {
    x: BigInt(babyJub.F.toObject(point[0])),
    y: BigInt(babyJub.F.toObject(point[1])),
  };
}

/** True when `privateScalar` is the decryption key for `publicKey`. Reveals nothing on failure. */
export async function monitorScalarMatchesKey(
  privateScalar: bigint,
  publicKey: BabyJubPublicKey,
): Promise<boolean> {
  const derived = await babyJubPublicKeyFromScalar(privateScalar);
  return derived.x === publicKey.x && derived.y === publicKey.y;
}

export async function decryptBabyJubTmCiphertext(
  payload: Uint8Array,
  monitorPrivateScalar: bigint,
  context: TmEncryptionContext,
): Promise<TmEncryptionPlaintext> {
  if (payload.length !== PAYLOAD_LENGTH || payload[0] !== VERSION) {
    throw new Error("GAP TM cipher: invalid payload");
  }
  const babyJub = await buildBabyjub();
  const scalar = monitorPrivateScalar % BigInt(babyJub.subOrder);
  if (scalar === 0n) throw new Error("GAP TM cipher: invalid private scalar");
  const ephemeral = toPoint(babyJub, {
    x: bytesToBigInt(payload.subarray(1, 33)),
    y: bytesToBigInt(payload.subarray(33, 65)),
  });
  const sharedPoint = babyJub.mulPointEscalar(ephemeral, scalar);
  const nonce = payload.subarray(65, 89);
  const sealed = payload.subarray(89);
  const key = deriveKey(pointBytes(babyJub, sharedPoint), context.monitorKeyId);
  const opened = xchacha20poly1305(key, nonce, encodeTmAad(context)).decrypt(sealed);
  const plaintext = decodeTmPlaintext(opened);
  assertPlaintext(plaintext);
  return plaintext;
}
