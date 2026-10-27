#!/usr/bin/env bash
#
# GATE (a): can the committed verifier be rebuilt from the committed circuit?
#
# `check-artifacts.mjs` asks whether the committed bundle is internally coherent: it re-derives
# the verification key and the Solidity verifier FROM THE COMMITTED ZKEY. That catches a hand-
# edited verifier, and nothing else: a zkey substituted wholesale, from a different circuit or a
# different phase-1 file, passes it cleanly because every downstream artifact agrees with the
# substitute. This script closes that hole by rebuilding the chain from source in a scratch tree
# and comparing digests.
#
# WHAT IS NOT COMPARED. Proof fixtures. Groth16 proving draws fresh randomness per proof, so two
# proofs over identical inputs and an identical key differ byte-for-byte and are BOTH valid. A
# gate that byte-diffed them would fail on every run and be disabled within a week. Their
# correctness is asserted where it belongs: a real proof through the on-chain verifier, in the
# Foundry suite.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
PTAU="$ROOT/powersOfTau28_hez_final_16.ptau"
MANIFEST="$ROOT/circuits/keys/v2/local-artifact-manifest.json"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/gap-v2-repro-XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

. "$ROOT/scripts/v2/lib/fetch-ptau.sh"
ensure_ptau "$PTAU" || exit 1
. "$ROOT/scripts/v2/lib/dev-beacon.sh"
# The compiler is an input; see the file. A gate that compiles with "whatever circom is on PATH"
# fails on an upstream release for reasons unrelated to the change under review.
. "$ROOT/scripts/v2/lib/fetch-circom.sh"
CIRCOM="$(ensure_circom "${GAP_CIRCOM_CACHE:-}")" || exit 1
echo "▸ compiler: $CIRCOM ($("$CIRCOM" --version))"

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

echo "▸ rebuilding the v2 chain from committed source into ${SCRATCH}…"
( cd circuits && "$CIRCOM" src/v2/session.circom --r1cs --wasm --sym -o "$SCRATCH" -l node_modules >/dev/null )
( cd circuits
  pnpm exec snarkjs groth16 setup "$SCRATCH/session.r1cs" "$PTAU" "$SCRATCH/session_0000.zkey" >/dev/null 2>&1
  pnpm exec snarkjs zkey beacon "$SCRATCH/session_0000.zkey" "$SCRATCH/session_final.zkey" \
    "$DEV_BEACON_HEX" "$DEV_BEACON_ITERATIONS" --name="$DEV_BEACON_NAME" >/dev/null 2>&1
  pnpm exec snarkjs zkey export verificationkey "$SCRATCH/session_final.zkey" \
    "$SCRATCH/verification_key.json" >/dev/null 2>&1
  pnpm exec snarkjs zkey export solidityverifier "$SCRATCH/session_final.zkey" \
    "$SCRATCH/SessionVerifier.sol" >/dev/null 2>&1
)
node scripts/v2/verifier-rewrite.mjs "$SCRATCH/SessionVerifier.sol" SessionVerifier development >/dev/null

FAILED=0
compare() {
  local field="$1" rebuilt="$2"
  local expected actual
  expected="$(jq -r ".$field" "$MANIFEST")"
  actual="$(digest "$rebuilt")"
  if [[ "$expected" == "$actual" ]]; then
    printf '  ✓ %-24s %s\n' "$field" "$actual"
  else
    printf '  ✗ %-24s manifest %s\n%29s rebuilt  %s\n' "$field" "$expected" "" "$actual"
    FAILED=1
  fi
}
compare r1csSha256             "$SCRATCH/session.r1cs"
compare wasmSha256             "$SCRATCH/session_js/session.wasm"
compare zkeySha256             "$SCRATCH/session_final.zkey"
compare verificationKeySha256  "$SCRATCH/verification_key.json"
compare solidityVerifierSha256 "$SCRATCH/SessionVerifier.sol"

# AND THE COMMITTED FILE, which is the half this check was missing. Everything above compares the
# REBUILD against the manifest: it proves manifest ≡ source. It never opened
# contracts/src/v2/SessionVerifier.sol, so it did not prove the committed verifier is the one the
# manifest describes. `artifact-check` does that, and is not in the four commands CONTRIBUTING names.
#
# The gap was not theoretical: three documents said editing this file, "even the comments, even the
# licence header", is a build failure, and a reviewer relicensed it from GPL-3.0 to Apache-2.0,
# reassigned its copyright, and watched every prescribed gate pass. A semantic edit was still caught
# by the real-proof test; a comment-only edit was caught by nothing.
compare solidityVerifierSha256 "$ROOT/contracts/src/v2/SessionVerifier.sol"

if [[ "$FAILED" != "0" ]]; then
  cat >&2 <<'MSG'

The committed v2 verifier is NOT reproducible from the committed circuit. Either the artifacts
were built from a source, phase-1 file, or toolchain that is not the one in this tree, or the
build script's close changed. Re-run `make build` and commit the whole bundle together.
MSG
  exit 1
fi
echo "✅ the committed v2 verifier rebuilds byte-for-byte from the committed circuit."
