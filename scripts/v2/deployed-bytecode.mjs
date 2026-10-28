// WHY A SOURCE DIGEST IS NOT A BINDING.
//
// `solidityVerifierSha256` hashes `SessionVerifier.sol`. It answers "is the file on disk the file
// the manifest was written against" and NOTHING about what is deployed. Two ways that gap bites:
//
//   1. Same source, different bytecode. Compiler version, optimizer settings and the trailing
//      solc metadata hash all move the runtime code without touching a byte of the .sol.
//   2. Different source, still MATCH. Regenerate the circuit, and the verifier and the manifest
//      are rewritten together, self-consistent, and describing a contract nobody deployed. This
//      is not hypothetical: an earlier circuit regeneration left a testnet deployment in exactly
//      this state, and the source-digest check reported MATCH throughout.
//
// So the binding is to the RUNTIME BYTECODE the chain actually returns. `deployedBytecodeSha256`
// is recorded from the same forge build that produced the deployment, and the check compares it
// against `eth_getCode`.
//
// WHEN THEY DIFFER, SAY WHY. A bare digest mismatch sends the reader to a hex diff. A Groth16
// verifier is mostly its verification key, so this also reports how many of the committed key's
// field elements appear in the deployed code, which separates "recompiled with other settings"
// (all present) from "this is a verifier for a different circuit" (almost none).
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export const digestOfCode = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** `0x…` runtime code to bytes. Empty or `0x` means no contract at that address. */
export function codeBytes(hex) {
  const body = String(hex ?? "").replace(/^0x/i, "");
  if (body.length === 0) return Buffer.alloc(0);
  if (!/^[0-9a-f]*$/i.test(body) || body.length % 2 !== 0) {
    throw new Error("eth_getCode did not return hex");
  }
  return Buffer.from(body, "hex");
}

// solc emits a constant with the NARROWEST push that holds it, so a field element whose top byte
// happens to be zero is 31 bytes in the bytecode, not 32. Searching for padded 32-byte words
// silently misses those, `IC14x` in the base-fund key is exactly one, and it made a correct build
// score 53/54 and never reach the "all present" branch. Minimal big-endian encoding it is.
/** Every field element of a Groth16 verification key, as the bytes a verifier actually embeds. */
export function verificationKeyWords(key) {
  const words = [];
  const push = (value) => words.push(BigInt(value));
  for (const point of [key.vk_alpha_1, ...(key.IC ?? [])]) {
    if (Array.isArray(point)) point.slice(0, 2).forEach(push);
  }
  for (const pair of [key.vk_beta_2, key.vk_gamma_2, key.vk_delta_2]) {
    if (Array.isArray(pair)) for (const half of pair.slice(0, 2)) half.slice(0, 2).forEach(push);
  }
  return words
    .map((value) => {
      const hex = value.toString(16);
      return Buffer.from(hex.length % 2 === 0 ? hex : `0${hex}`, "hex");
    })
    // A short needle matches by chance. Field elements are ~32 bytes, so this drops nothing real;
    // it only stops a degenerate key from reporting a confident, meaningless "all present".
    .filter((word) => word.length >= 16);
}

/** How much of a verification key is embedded in some runtime code. */
export function keyPresence(code, key) {
  const words = verificationKeyWords(key);
  const found = words.filter((word) => code.includes(word)).length;
  return { found, total: words.length };
}

export async function readVerificationKey(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

/**
 * The verdict, and enough of the why to act on it.
 *
 * @param {object} input
 * @param {Buffer} input.deployed        runtime code from eth_getCode
 * @param {string} input.expectedSha256  deployedBytecodeSha256 from the artifact manifest
 * @param {object} [input.verificationKey] the committed key, for the diagnosis
 */
export function bindingVerdict({ deployed, expectedSha256, verificationKey }) {
  if (deployed.length === 0) {
    return { ok: false, reason: "no-contract", detail: "the address holds no code" };
  }
  const actual = digestOfCode(deployed);
  if (actual === String(expectedSha256).toLowerCase()) {
    return { ok: true, sha256: actual, bytes: deployed.length };
  }
  let detail = `deployed sha256 ${actual} != manifest ${expectedSha256}`;
  if (verificationKey) {
    const { found, total } = keyPresence(deployed, verificationKey);
    detail += found === total
      ? ": the committed verification key IS embedded, so the difference is compiler settings " +
        "or metadata, not the circuit"
      : `, only ${found}/${total} of the committed verification key's field elements appear in ` +
        "the deployed code: this is a verifier for a DIFFERENT circuit, and proofs from the " +
        "committed artifacts cannot satisfy it";
  }
  return { ok: false, reason: "mismatch", sha256: actual, detail };
}
