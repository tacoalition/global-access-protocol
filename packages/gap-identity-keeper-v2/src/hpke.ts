import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

const KEM_ID = 0x20;
const KDF_ID = 0x01;
const AEAD_ID = 0x03;
const HPKE_VERSION = Buffer.from("HPKE-v1", "ascii");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

function concat(...values: readonly Uint8Array[]): Buffer {
  return Buffer.concat(values.map((value) => Buffer.from(value)));
}

function i2osp(value: number, length: number): Buffer {
  const output = Buffer.alloc(length);
  output.writeUIntBE(value, 0, length);
  return output;
}

function extract(salt: Uint8Array, ikm: Uint8Array): Buffer {
  return createHmac("sha256", salt.length === 0 ? Buffer.alloc(32) : salt).update(ikm).digest();
}

function expand(prk: Uint8Array, info: Uint8Array, length: number): Buffer {
  if (length > 255 * 32) throw new Error("HKDF output too large");
  const blocks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; Buffer.concat(blocks).length < length; counter += 1) {
    previous = createHmac("sha256", prk).update(concat(previous, info, Uint8Array.of(counter))).digest();
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function labeledExtract(suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Buffer {
  return extract(salt, concat(HPKE_VERSION, suite, Buffer.from(label, "ascii"), ikm));
}

function labeledExpand(
  suite: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Buffer {
  return expand(prk, concat(i2osp(length, 2), HPKE_VERSION, suite, Buffer.from(label, "ascii"), info), length);
}

function importPublic(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return createPublicKey({ key: concat(X25519_SPKI_PREFIX, raw), format: "der", type: "spki" });
}

function importPrivate(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error("X25519 private key must be 32 bytes");
  return createPrivateKey({ key: concat(X25519_PKCS8_PREFIX, raw), format: "der", type: "pkcs8" });
}

function exportPublic(key: KeyObject): Buffer {
  return Buffer.from(key.export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
}

function recipientSharedSecret(recipientPrivate: KeyObject, enc: Uint8Array): Buffer {
  const recipientPublic = exportPublic(createPublicKey(recipientPrivate));
  const kemSuite = concat(Buffer.from("KEM", "ascii"), i2osp(KEM_ID, 2));
  const dh = diffieHellman({ privateKey: recipientPrivate, publicKey: importPublic(enc) });
  const kemContext = concat(enc, recipientPublic);
  const eaePrk = labeledExtract(kemSuite, new Uint8Array(), "eae_prk", dh);
  return labeledExpand(kemSuite, eaePrk, "shared_secret", kemContext, 32);
}

function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): { key: Buffer; nonce: Buffer } {
  const suite = concat(Buffer.from("HPKE", "ascii"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
  const pskIdHash = labeledExtract(suite, new Uint8Array(), "psk_id_hash", new Uint8Array());
  const infoHash = labeledExtract(suite, new Uint8Array(), "info_hash", info);
  const context = concat(Uint8Array.of(0), pskIdHash, infoHash);
  const secret = labeledExtract(suite, sharedSecret, "secret", new Uint8Array());
  return {
    key: labeledExpand(suite, secret, "key", context, 32),
    nonce: labeledExpand(suite, secret, "base_nonce", context, 12),
  };
}

export interface HpkeCiphertext {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export function generateX25519RawKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const pair = generateKeyPairSync("x25519");
  return {
    publicKey: exportPublic(pair.publicKey),
    privateKey: Buffer.from(pair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32),
  };
}

export function hpkeSeal(
  recipientPublic: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  ephemeralPrivateRaw?: Uint8Array,
): HpkeCiphertext {
  const ephemeralPrivate = ephemeralPrivateRaw ? importPrivate(ephemeralPrivateRaw) : generateKeyPairSync("x25519").privateKey;
  const enc = exportPublic(createPublicKey(ephemeralPrivate));
  const kemSuite = concat(Buffer.from("KEM", "ascii"), i2osp(KEM_ID, 2));
  const dh = diffieHellman({ privateKey: ephemeralPrivate, publicKey: importPublic(recipientPublic) });
  const eaePrk = labeledExtract(kemSuite, new Uint8Array(), "eae_prk", dh);
  const sharedSecret = labeledExpand(kemSuite, eaePrk, "shared_secret", concat(enc, recipientPublic), 32);
  const { key, nonce } = keySchedule(sharedSecret, info);
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { enc, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

export function hpkeOpen(
  recipientPrivateRaw: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (enc.length !== 32 || ciphertext.length < 16) throw new Error("malformed HPKE ciphertext");
  const sharedSecret = recipientSharedSecret(importPrivate(recipientPrivateRaw), enc);
  const { key, nonce } = keySchedule(sharedSecret, info);
  const body = Buffer.from(ciphertext).subarray(0, -16);
  const tag = Buffer.from(ciphertext).subarray(-16);
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(aad), { plaintextLength: body.length });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}
