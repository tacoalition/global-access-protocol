// CLI/sidecar binding of the @tac-gap/sdk proving core to the LOCAL crypto module + Groth16 artifacts.
// The reusable logic lives in packages/gap-sdk; this file just injects Node-specific config and
// re-exports the same surface the CLI flows already import.
import { createBabyJubTmCipher } from "@tac-gap/sdk";
import { monitorKeyFor } from "./monitor-key";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { groth16 } from "snarkjs";
import {
  createGapProver,
  formatProof,
  type ArtifactReference,
  type Hex,
} from "@tac-gap/sdk";
export type { Holder, SessionScenario, SessionInput } from "@tac-gap/sdk";

const gc = require(path.resolve(__dirname, "../../../circuits/scripts/v2/gap_crypto.js"));
const ROOT = path.resolve(__dirname, "../../..");
const WASM = path.join(ROOT, "circuits/build/v2/session_js/session.wasm");
const ZKEY = path.join(ROOT, "circuits/keys/v2/session_final.zkey");
const VKEY = path.join(ROOT, "circuits/keys/v2/verification_key.json");
const MANIFEST = path.join(ROOT, "circuits/keys/v2/local-artifact-manifest.json");

let manifest: Record<string, unknown> | undefined;
function manifestDigest(field: string): Hex {
  // JSON.parse returns `any`, so annotate the load to keep `manifest` narrowable below.
  manifest ??= JSON.parse(fs.readFileSync(MANIFEST, "utf8")) as Record<string, unknown>;
  const value = manifest[field];
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error(
      `GAP CLI: local artifact manifest field ${field} is missing; run "make build"`,
    );
  }
  return `0x${value.toLowerCase()}`;
}

function artifact(source: string, manifestField: string): ArtifactReference {
  return {
    source,
    get sha256() {
      return manifestDigest(manifestField);
    },
  };
}

async function verifyFileArtifact(reference: ArtifactReference): Promise<void> {
  const source = reference.source;
  if (typeof source !== "string") {
    throw new Error("GAP CLI: expected a filesystem artifact");
  }
  const actual = await new Promise<string>((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = fs.createReadStream(source);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
  const expected = reference.sha256.replace(/^0x/, "").toLowerCase();
  if (actual !== expected) {
    throw new Error(
      `GAP CLI: artifact digest mismatch for ${source}; run "make build"`,
    );
  }
}


const prover = createGapProver({
  crypto: gc,
  groth16,
  wasm: artifact(WASM, "wasmSha256"),
  zkey: artifact(ZKEY, "zkeySha256"),
  verificationKey: artifact(VKEY, "verificationKeySha256"),
  verifyArtifact: verifyFileArtifact,
  // Lazily, and once: the prover config is built at module load and top-level await is not
  // available under this tsconfig. The SDK calls `tmCipher` only when it seals an envelope.
  tmCipher: {
    async encrypt(plaintext, context) {
      // THE KEY THE CHAIN DECLARES, not a compile-time constant. `context.monitorKeyId` is the id the
      // proof commits to and the SessionManager checks, so sealing to anything else produces an
      // envelope that passes every on-chain gate and no monitor can open.
      const point = monitorKeyFor(context.monitorKeyId);
      const cipher = await createBabyJubTmCipher({ monitorPublicKey: point });
      return cipher.encrypt(plaintext, context);
    },
  },
});

export const credentialCommitment = prover.credentialCommitment;
export const pseudonymFor = prover.pseudonymFor;
export const saltCommitment = prover.saltCommitment;
export const spendingKeyRootFor = prover.spendingKeyRootFor;
export const buildSessionInput = prover.buildSessionInput;
export const buildSessionInputFromWitness = prover.buildSessionInputFromWitness;
export const proveInputServer = prover.proveInputServer;
export { formatProof };

/** Server-side proof: build the input then run Groth16 locally (unchanged behavior). */
export async function buildProof(s: import("@tac-gap/sdk").SessionScenario) {
  const { input, ciphertext, tmContext, pseudonym, roots } = await prover.buildSessionInput(s);
  const { pA, pB, pC, pub, provingMs } = await prover.proveInputServer(input);
  return { pA, pB, pC, pub, ciphertext, tmContext, pseudonym, provingMs, roots };
}
