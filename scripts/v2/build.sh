#!/usr/bin/env bash
# GAP v2, compile the circuit, run the trusted setup, export the on-chain verifier, build contracts.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
PTAU="$ROOT/powersOfTau28_hez_final_16.ptau"

# THE COMPILER IS AN INPUT, AND IT HAS TO BE PRESENT. This called bare `circom`, so a machine
# without it failed at the very first step of the very first command with "circom: command not
# found", while the README and golden-path.sh both said this step fetches circom. The fetcher
# existed and had a pinned version and a per-platform digest; only `make repro` ever called it.
# Same idiom here, so a fresh clone gets the pinned compiler rather than an error.
# shellcheck source=scripts/v2/lib/fetch-circom.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/fetch-circom.sh"
CIRCOM="$(ensure_circom "${GAP_CIRCOM_CACHE:-}")" || exit 1

echo "▸ compiling session circuit…  ($("$CIRCOM" --version))"
mkdir -p circuits/build/v2 circuits/keys/v2
( cd circuits && "$CIRCOM" src/v2/session.circom --r1cs --wasm --sym -o build/v2 -l node_modules )
INFO=$(cd circuits && pnpm exec snarkjs r1cs info build/v2/session.r1cs 2>&1)
CONSTRAINTS=$(printf '%s\n' "$INFO" | sed -n 's/.*# of Constraints: *//p' | tail -1)
PUBLIC_INPUTS=$(printf '%s\n' "$INFO" | sed -n 's/.*# of Public Inputs: *//p' | tail -1)
echo "  constraints: $CONSTRAINTS  (depth-16 DID/credential profile, 8 attributes, MAX_CLAUSES=6)"
[[ "$CONSTRAINTS" == "59143" ]] || {
  echo "expected 59143 constraints, got $CONSTRAINTS" >&2
  exit 1
}
[[ "$PUBLIC_INPUTS" == "19" ]] || {
  echo "expected 19 public inputs, got $PUBLIC_INPUTS" >&2
  exit 1
}

# Fetch-and-verify, or refuse. See scripts/v2/lib/fetch-ptau.sh for why an unverified phase-1
# file makes every downstream contribution meaningless.
# shellcheck source=scripts/v2/lib/fetch-ptau.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/fetch-ptau.sh"
ensure_ptau "$PTAU" || exit 1

# Deterministic close, so the verifier below can be regenerated from source. See the file for why
# `zkey contribute` cannot be, and why this value being public is deliberate.
# shellcheck source=scripts/v2/lib/dev-beacon.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/dev-beacon.sh"

echo "▸ groth16 DEVELOPMENT setup (deterministic beacon, not a ceremony)…"
( cd circuits
  pnpm exec snarkjs groth16 setup build/v2/session.r1cs "$PTAU" keys/v2/session_0000.zkey >/dev/null 2>&1
  pnpm exec snarkjs zkey beacon keys/v2/session_0000.zkey keys/v2/session_final.zkey \
    "$DEV_BEACON_HEX" "$DEV_BEACON_ITERATIONS" --name="$DEV_BEACON_NAME" >/dev/null 2>&1
  pnpm exec snarkjs zkey export verificationkey keys/v2/session_final.zkey keys/v2/verification_key.json >/dev/null 2>&1
  pnpm exec snarkjs zkey export solidityverifier keys/v2/session_final.zkey "$ROOT/contracts/src/v2/SessionVerifier.sol" >/dev/null 2>&1
)
# One definition of the committed form, shared with check-artifacts.mjs, see the module header.
node scripts/v2/verifier-rewrite.mjs contracts/src/v2/SessionVerifier.sol SessionVerifier development
echo "  verifier → contracts/src/v2/SessionVerifier.sol"

# Contracts BEFORE the manifest: the manifest records the verifier's DEPLOYED BYTECODE, which
# only exists once forge has compiled it. Recording it from a stale build is how a manifest ends
# up describing a contract nobody deployed, see scripts/v2/deployed-bytecode.mjs.
echo "▸ building contracts…"
( cd contracts && forge build >/dev/null 2>&1 )

echo "▸ regenerating proof fixtures + manifest…"
( cd circuits && node scripts/v2/prove_session.js selftest )
node scripts/v2/update-artifact-manifest.mjs
node scripts/v2/check-artifacts.mjs
echo "✅ build complete."
