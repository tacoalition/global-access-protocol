#!/usr/bin/env bash
# GAP v2, client-custody WELL-FORMEDNESS circuits: compile, DEV phase-2 setup, pin the artifacts.
#
#   scripts/v2/build-wf.sh            build if the pins do not already verify (idempotent)
#   scripts/v2/build-wf.sh --force    rebuild and re-run the development ceremony unconditionally
#   scripts/v2/build-wf.sh --check    verify only; never compiles, never touches a key
#
# ⚠️  THE KEYS THIS SCRIPT PRODUCES ARE DEVELOPMENT ARTIFACTS. The phase-2 setup below is a
# SINGLE contribution with a fixed, checked-in entropy string, run on one machine by whoever
# typed the command. Anyone holding this repo can reproduce the toxic waste, so any proof
# verified under these keys proves nothing to anyone but a local test. `pins.json` records
# `"ceremony": "DEV_SINGLE_CONTRIBUTION"` and `"developmentOnly": true` so a consumer cannot
# mistake them, and `packages/gap-sdk/test/wf-proofs.test.ts` asserts both.
#
# FOLLOW-UP; THE PRODUCTION CEREMONY, which is deliberately NOT run here. The harness for it now
# exists at `scripts/v2/wf-ceremony.sh` (policy in `wf-ceremony-transcript.mjs`), and it writes to
# a SEPARATE build directory so a ceremony in progress cannot disturb a lane running on these dev
# keys. It cannot flip `developmentOnly` without a transcript carrying distinct contributors, a
# closing beacon and a passing verification: there is no --force. What it cannot supply is the
# one thing that matters: the independent participants. The steps it automates are:
#   1. Size the powers-of-tau to the largest circuit (wf_cred, 4,783 constraints → 2^13 suffices;
#      the repo's 2^16 file is used only because the v2 lane already carries it).
#   2. Per circuit, run a MULTI-contributor phase 2: `snarkjs zkey contribute` once per
#      independent participant, each supplying their own entropy on their own machine, then
#      `snarkjs zkey beacon` with a public randomness beacon to close it.
#   3. `snarkjs zkey verify <r1cs> <ptau> <final.zkey>` and publish the full transcript
#      (`snarkjs zkey export bellman` / the contribution hashes) so a third party can audit it.
#   4. Re-pin: regenerate pins.json, promote the digests into whatever production metadata the IK
#      loads, and flip `developmentOnly` off: a build that has not done step 3 must not flip it.
# The v2 session lane has the identical debt; `V2_PRODUCTION_HARDENING.md (full stack, not in this repository)` is where
# that one is tracked and where this list belongs when the two are scheduled together.

set -euo pipefail

# The pinned compiler, same as build.sh and repro-check.sh: bare `circom` fails on a fresh
# clone with "command not found", and an unpinned one compiles a different circuit.
# shellcheck source=scripts/v2/lib/fetch-circom.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/fetch-circom.sh"
CIRCOM="$(ensure_circom "${GAP_CIRCOM_CACHE:-}")" || exit 1
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

PTAU="$ROOT/powersOfTau28_hez_final_16.ptau"
BUILD="$ROOT/circuits/build/wf"
KEYS="$BUILD/keys"
PINS="$BUILD/pins.json"
MODE="${1:-build}"

# name : main source (relative to circuits/) : constraints : public inputs
#
# THESE FOUR NUMBERS ARE THE MIRROR. The public-signal counts must equal the layouts in
# packages/gap-sdk/src/wf-layout.ts (asserted by packages/gap-sdk/test/wf-circuits.test.ts, which
# parses THIS table) and the `{public [...]}` lists in circuits/src/v2/wf_*.circom. The session
# circuit's lesson is that a public count mirrored in three places and checked in none is a
# defect waiting for a deployment; these are checked in all of them.
CIRCUITS=(
  "wf_salt_binding:src/v2/wf_salt_binding.circom:517:1"
  "wf_cred:src/v2/wf_cred.circom:5132:8"
  "wf_pseudonym:src/v2/wf_pseudonym.circom:2068:6"
)

CRED_TAG="7398619034839472060957547841361825911550539606183619483712186628328937676175"

# EVERY source an artifact depends on, not just the main wrapper.
# `--check` never recompiles, so a pin over the wrapper alone would pass happily while the
# statement itself had been edited underneath it: the wrappers are eleven lines each and the
# whole meaning lives in the libs. `policy.circom` is here because `H2Chain` is the fold all
# three circuits are built from, the session lane owns that file, and a change to it is a change
# to these circuits whether or not anyone rebuilt them.
WF_SOURCES=(
  circuits/src/v2/lib/policy.circom
  circuits/src/v2/lib/wf_gadgets.circom
  circuits/src/v2/lib/salt_binding.circom
  circuits/src/v2/lib/cred_wf.circom
  circuits/src/v2/lib/pseudonym_wf.circom
  circuits/src/v2/wf_salt_binding.circom
  circuits/src/v2/wf_cred.circom
  circuits/src/v2/wf_pseudonym.circom
)

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
sources_digest() { ( cd "$ROOT" && shasum -a 256 "${WF_SOURCES[@]}" | shasum -a 256 | cut -d' ' -f1 ); }
fail() { echo "✗ $*" >&2; exit 1; }

paths_for() { # $1 = name → emits "source r1cs wasm zkey vkey", all repo-relative
  printf 'circuits/%s circuits/build/wf/%s.r1cs circuits/build/wf/%s_js/%s.wasm circuits/build/wf/keys/%s_final.zkey circuits/build/wf/keys/%s_vkey.json' \
    "$2" "$1" "$1" "$1" "$1" "$1"
}

r1cs_field() { # $1 = r1cs path, $2 = field label
  ( cd "$ROOT/circuits" && FORCE_COLOR=0 pnpm exec snarkjs r1cs info "$1" 2>&1 ) \
    | sed -n "s/.*# of $2: *//p" | tail -1 | tr -d '\r'
}

assert_tag_mirror() {
  grep -q "$CRED_TAG" "$ROOT/circuits/src/v2/lib/gap_session.circom" \
    || fail "the credential tag in gap_session.circom is no longer $CRED_TAG"
  grep -q "$CRED_TAG" "$ROOT/circuits/src/v2/lib/wf_gadgets.circom" \
    || fail "wf_gadgets.circom does not carry the session circuit's credential tag"
}

verify_pins() { # 0 = every artifact present and matching; 1 = rebuild needed
  [ -f "$PINS" ] || { echo "  pins.json absent"; return 1; }
  local sources
  sources=$(sed -n 's/.*"sourcesSha256": "0x\([0-9a-f]*\)".*/\1/p' "$PINS" | tail -1)
  [ "$sources" = "$(sources_digest)" ] || { echo "  circuit sources changed since these artifacts were built"; return 1; }
  for entry in "${CIRCUITS[@]}"; do
    IFS=: read -r name source constraints publics <<<"$entry"
    # shellcheck disable=SC2046
    set -- $(paths_for "$name" "$source")
    local kinds=(source r1cs wasm zkey verificationKey)
    local index=1
    for kind in "${kinds[@]}"; do
      local file="${!index}"
      [ -f "$ROOT/$file" ] || { echo "  $name: missing $file"; return 1; }
      local pinned
      pinned=$(sed -n "/\"$name\":/,/^    }/p" "$PINS" | sed -n "s/.*\"$kind\": \"0x\([0-9a-f]*\)\".*/\1/p" | tail -1)
      [ -n "$pinned" ] || { echo "  $name: $kind is not pinned"; return 1; }
      [ "$pinned" = "$(sha "$ROOT/$file")" ] || { echo "  $name: $kind does not match its pin"; return 1; }
      index=$((index + 1))
    done
    local actual
    actual=$(r1cs_field "build/wf/$name.r1cs" "Constraints")
    [ "$actual" = "$constraints" ] || { echo "  $name: expected $constraints constraints, got $actual"; return 1; }
    actual=$(r1cs_field "build/wf/$name.r1cs" "Public Inputs")
    [ "$actual" = "$publics" ] || { echo "  $name: expected $publics public inputs, got $actual"; return 1; }
  done
  return 0
}

write_pins() {
  {
    printf '{\n  "schemaVersion": 1,\n  "profile": "gap-wf-dev",\n'
    printf '  "developmentOnly": true,\n  "ceremony": "DEV_SINGLE_CONTRIBUTION",\n'
    printf '  "ptau": "powersOfTau28_hez_final_16.ptau",\n'
    printf '  "sourcesSha256": "0x%s",\n  "circuits": {\n' "$(sources_digest)"
    local first=1
    for entry in "${CIRCUITS[@]}"; do
      IFS=: read -r name source constraints publics <<<"$entry"
      # shellcheck disable=SC2046
      set -- $(paths_for "$name" "$source")
      [ $first -eq 1 ] || printf ',\n'
      first=0
      printf '    "%s": {\n      "source": "%s",\n      "constraints": %s,\n      "publicInputs": %s,\n' \
        "$name" "$1" "$constraints" "$publics"
      printf '      "r1cs": "%s",\n      "wasm": "%s",\n      "zkey": "%s",\n      "verificationKey": "%s",\n' \
        "$2" "$3" "$4" "$5"
      printf '      "sha256": {\n        "source": "0x%s",\n        "r1cs": "0x%s",\n        "wasm": "0x%s",\n        "zkey": "0x%s",\n        "verificationKey": "0x%s"\n      }\n    }' \
        "$(sha "$ROOT/$1")" "$(sha "$ROOT/$2")" "$(sha "$ROOT/$3")" "$(sha "$ROOT/$4")" "$(sha "$ROOT/$5")"
    done
    printf '\n  }\n}\n'
  } >"$PINS"
}

case "$MODE" in
  --check)
    assert_tag_mirror
    if verify_pins; then
      echo "✅ well-formedness artifacts are coherent with their pins."
    else
      fail "well-formedness artifacts are incoherent; run scripts/v2/build-wf.sh --force"
    fi
    exit 0
    ;;
  --force) ;;
  build)
    assert_tag_mirror
    if verify_pins >/dev/null 2>&1; then
      echo "✅ well-formedness artifacts already coherent: nothing to do (--force to rebuild)."
      exit 0
    fi
    ;;
  *) fail "usage: $0 [build|--force|--check]" ;;
esac

assert_tag_mirror
mkdir -p "$BUILD" "$KEYS"

echo "▸ compiling well-formedness circuits…"
for entry in "${CIRCUITS[@]}"; do
  IFS=: read -r name source constraints publics <<<"$entry"
  ( cd "$ROOT/circuits" && "$CIRCOM" "$source" --r1cs --wasm --sym -o build/wf -l node_modules >/dev/null )
  actual=$(r1cs_field "build/wf/$name.r1cs" "Constraints")
  [ "$actual" = "$constraints" ] || fail "$name: expected $constraints constraints, got $actual"
  actual=$(r1cs_field "build/wf/$name.r1cs" "Public Inputs")
  [ "$actual" = "$publics" ] || fail "$name: expected $publics public inputs, got $actual"
  echo "  $name: $constraints constraints, $publics public inputs"
done

# Fetch-and-verify, or refuse. See scripts/v2/lib/fetch-ptau.sh for why an unverified phase-1
# file makes every downstream contribution meaningless.
# shellcheck source=scripts/v2/lib/fetch-ptau.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/fetch-ptau.sh"
ensure_ptau "$PTAU" || exit 1

# shellcheck source=scripts/v2/lib/dev-beacon.sh
. "$ROOT/scripts/v2/lib/dev-beacon.sh"
echo "▸ groth16 DEVELOPMENT setup (deterministic beacon, not a production ceremony)…"
for entry in "${CIRCUITS[@]}"; do
  IFS=: read -r name source constraints publics <<<"$entry"
  ( cd "$ROOT/circuits"
    pnpm exec snarkjs groth16 setup "build/wf/$name.r1cs" "$PTAU" "build/wf/keys/${name}_0000.zkey" >/dev/null 2>&1
    pnpm exec snarkjs zkey beacon \
      "build/wf/keys/${name}_0000.zkey" "build/wf/keys/${name}_final.zkey" \
      "$DEV_BEACON_HEX" "$DEV_BEACON_ITERATIONS" --name="$DEV_BEACON_NAME" >/dev/null 2>&1
    pnpm exec snarkjs zkey export verificationkey \
      "build/wf/keys/${name}_final.zkey" "build/wf/keys/${name}_vkey.json" >/dev/null 2>&1 ) \
    || fail "$name: development setup failed, rerun the snarkjs commands without the >/dev/null to see why"
  rm -f "$KEYS/${name}_0000.zkey"
  echo "  $name → build/wf/keys/${name}_final.zkey + _vkey.json"
done

write_pins
verify_pins >/dev/null || fail "pins written but do not verify"
echo "✅ well-formedness build complete → circuits/build/wf/pins.json (DEVELOPMENT ONLY)."
