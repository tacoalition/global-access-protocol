export type CborValue =
  | null
  | bigint
  | number
  | string
  | Uint8Array
  | readonly CborValue[]
  | ReadonlyMap<number, CborValue>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function uintBytes(value: bigint, bytes: number): Uint8Array {
  const output = new Uint8Array(bytes);
  for (let i = bytes - 1; i >= 0; i -= 1) {
    output[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return output;
}

function head(major: number, value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new Error("CBOR uint out of range");
  if (value < 24n) return Uint8Array.of((major << 5) | Number(value));
  if (value <= 0xffn) return concat([Uint8Array.of((major << 5) | 24), uintBytes(value, 1)]);
  if (value <= 0xffffn) return concat([Uint8Array.of((major << 5) | 25), uintBytes(value, 2)]);
  if (value <= 0xffffffffn) return concat([Uint8Array.of((major << 5) | 26), uintBytes(value, 4)]);
  return concat([Uint8Array.of((major << 5) | 27), uintBytes(value, 8)]);
}

export function cborMap(entries: readonly (readonly [number, CborValue])[]): ReadonlyMap<number, CborValue> {
  const sorted = [...entries].sort(([a], [b]) => a - b);
  if (sorted.some(([key], index) => index > 0 && sorted[index - 1][0] === key)) {
    throw new Error("duplicate CBOR map key");
  }
  return new Map(sorted);
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (value === null) return Uint8Array.of(0xf6);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("CBOR numbers must be unsigned safe integers");
    return head(0, BigInt(value));
  }
  if (typeof value === "bigint") return head(0, value);
  if (typeof value === "string") {
    const encoded = textEncoder.encode(value);
    return concat([head(3, BigInt(encoded.length)), encoded]);
  }
  if (value instanceof Uint8Array) return concat([head(2, BigInt(value.length)), value]);
  if (Array.isArray(value)) {
    return concat([head(4, BigInt(value.length)), ...value.map((item) => encodeCbor(item))]);
  }
  if (value instanceof Map) {
    const entries = [...value.entries()];
    for (let i = 0; i < entries.length; i += 1) {
      const [key] = entries[i];
      if (!Number.isSafeInteger(key) || key < 0 || (i > 0 && entries[i - 1][0] >= key)) {
        throw new Error("CBOR map keys must be strictly increasing unsigned integers");
      }
    }
    return concat([
      head(5, BigInt(entries.length)),
      ...entries.flatMap(([key, item]) => [head(0, BigInt(key)), encodeCbor(item)]),
    ]);
  }
  throw new Error("unsupported CBOR value");
}

class Decoder {
  private offset = 0;
  constructor(private readonly input: Uint8Array) {}

  complete(): boolean {
    return this.offset === this.input.length;
  }

  private take(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.input.length) throw new Error("truncated CBOR");
    const value = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  private argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const widths: Record<number, number> = { 24: 1, 25: 2, 26: 4, 27: 8 };
    const width = widths[additional];
    if (!width) throw new Error("indefinite/reserved CBOR length is forbidden");
    let value = 0n;
    for (const byte of this.take(width)) value = (value << 8n) | BigInt(byte);
    const minima: Record<number, bigint> = { 1: 24n, 2: 256n, 4: 65536n, 8: 4294967296n };
    if (value < minima[width]) throw new Error("non-minimal CBOR integer");
    return value;
  }

  value(): CborValue {
    const initial = this.take(1)[0];
    const major = initial >> 5;
    const additional = initial & 31;
    if (major === 7) {
      if (initial === 0xf6) return null;
      throw new Error("CBOR floats/tags/simple values are forbidden");
    }
    const argument = this.argument(additional);
    if (major === 0) return argument;
    if (argument > BigInt(Number.MAX_SAFE_INTEGER)) {
      if (major !== 0) throw new Error("CBOR container too large");
    }
    const length = Number(argument);
    if (major === 2) return this.take(length);
    if (major === 3) return textDecoder.decode(this.take(length));
    if (major === 4) return Array.from({ length }, () => this.value());
    if (major === 5) {
      const map = new Map<number, CborValue>();
      let previous = -1;
      for (let i = 0; i < length; i += 1) {
        const key = this.value();
        if (typeof key !== "bigint" || key > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("invalid CBOR map key");
        const numericKey = Number(key);
        if (numericKey <= previous) throw new Error("duplicate/out-of-order CBOR map key");
        previous = numericKey;
        map.set(numericKey, this.value());
      }
      return map;
    }
    throw new Error("negative integers and tags are forbidden");
  }
}

export function decodeCanonicalCbor(input: Uint8Array): CborValue {
  const decoder = new Decoder(input);
  const value = decoder.value();
  if (!decoder.complete()) throw new Error("trailing CBOR bytes");
  const encoded = encodeCbor(value);
  if (!Buffer.from(encoded).equals(Buffer.from(input))) throw new Error("noncanonical CBOR encoding");
  return value;
}

export function requireMap(value: CborValue, expectedKeys: readonly number[]): ReadonlyMap<number, CborValue> {
  if (!(value instanceof Map)) throw new Error("expected CBOR map");
  const keys = [...value.keys()];
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    throw new Error("unexpected CBOR map keys");
  }
  return value;
}
