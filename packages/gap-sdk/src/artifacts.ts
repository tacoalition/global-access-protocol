import type { ArtifactReference, Hex } from "./types";
import type { CircuitMetadata } from "./metadata";
import { bytesToHex } from "./random";

function normalizeDigest(value: string): string {
  return value.toLowerCase().replace(/^0x/, "");
}

export function assertArtifactPins(
  metadata: CircuitMetadata,
  artifacts: {
    readonly wasm?: ArtifactReference;
    readonly zkey?: ArtifactReference;
    readonly verificationKey?: ArtifactReference;
  },
): void {
  const pins = metadata.artifactDigests;
  if (metadata.profile === "base-fund-production") {
    if (!pins?.wasm || !pins.zkey || !pins.verificationKey) {
      throw new Error("GAP SDK: production metadata must pin wasm, zkey, and verification-key digests");
    }
  }
  for (const name of ["wasm", "zkey", "verificationKey"] as const) {
    const artifact = artifacts[name];
    if (!artifact) continue;
    const pinned = pins?.[name];
    if (!pinned) {
      if (metadata.profile === "base-fund-production") {
        throw new Error(`GAP SDK: production metadata does not pin ${name}`);
      }
      continue;
    }
    if (normalizeDigest(artifact.sha256) !== normalizeDigest(pinned)) {
      throw new Error(`GAP SDK: ${name} reference does not match circuit metadata`);
    }
  }
}

export async function sha256Hex(bytes: Uint8Array): Promise<Hex> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer);
  return bytesToHex(new Uint8Array(digest));
}

export async function verifyArtifactBytes(artifact: ArtifactReference): Promise<void> {
  if (!(artifact.source instanceof Uint8Array)) {
    throw new Error("GAP SDK: path/URL artifacts require an injected artifact verifier");
  }
  const actual = await sha256Hex(artifact.source);
  if (normalizeDigest(actual) !== normalizeDigest(artifact.sha256)) {
    throw new Error(
      `GAP SDK: artifact digest mismatch: expected ${artifact.sha256}, got ${actual}`,
    );
  }
}

export async function verifyConfiguredArtifacts(
  artifacts: readonly ArtifactReference[],
  verifier = verifyArtifactBytes,
): Promise<void> {
  await Promise.all(artifacts.map((artifact) => verifier(artifact)));
}
