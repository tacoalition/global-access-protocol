import { P } from "./types";

const TWO_256 = 1n << 256n;
const FIELD_SAMPLE_LIMIT = TWO_256 - (TWO_256 % P);

export type RandomBytes = (length: number) => Uint8Array;

export const secureRandomBytes: RandomBytes = (length) => {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new Error("GAP SDK: random byte length must be positive");
  }
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new Error("GAP SDK: Web Crypto CSPRNG unavailable");
  }
  return cryptoApi.getRandomValues(new Uint8Array(length));
};

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bigIntToBytes(value: bigint, length = 32): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) {
    throw new Error(`GAP SDK: value does not fit in ${length} bytes`);
  }
  const out = new Uint8Array(length);
  let remaining = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function hexToBytes(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error("GAP SDK: invalid hex");
  }
  return Uint8Array.from(hex.match(/.{2}/g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

/** Unbiased BN254 field sampling. */
export function sampleField(randomBytes: RandomBytes = secureRandomBytes, nonZero = true): bigint {
  for (;;) {
    const bytes = randomBytes(32);
    if (bytes.length !== 32) throw new Error("GAP SDK: random source returned the wrong byte length");
    const candidate = bytesToBigInt(bytes);
    if (candidate >= FIELD_SAMPLE_LIMIT) continue;
    const value = candidate % P;
    if (!nonZero || value !== 0n) return value;
  }
}
