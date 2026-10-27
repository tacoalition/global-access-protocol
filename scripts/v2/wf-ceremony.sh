#!/usr/bin/env bash
# GAP v2: the PRODUCTION phase-2 ceremony for the well-formedness circuits.
#
#   scripts/v2/wf-ceremony.sh init                 compile, size the ptau, open the transcript
#   scripts/v2/wf-ceremony.sh contribute "<name>"  ONE participant's contribution
#   scripts/v2/wf-ceremony.sh beacon <hex> [iters] close the ceremony on public randomness
#   scripts/v2/wf-ceremony.sh verify               snarkjs zkey verify, recorded
#   scripts/v2/wf-ceremony.sh promote              production pins, refuses unless earned
#   scripts/v2/wf-ceremony.sh status               where this ceremony is
#
# WHAT THIS IS NOT. `build-wf.sh` runs a DEVELOPMENT setup: one contribution, a checked-in entropy
# string, one machine. Anyone with this repo reproduces its toxic waste. This is the other thing,
# and the difference is not the script: it is the PEOPLE. Each `contribute` must be run by a
# different participant, on their own machine, with entropy they generate and then destroy. A
# ceremony where one person runs `contribute` three times under three names has three names and
# one party, and the transcript's guard exists because that is the failure that actually happens.
#
# THE OPERATOR CANNOT FLIP THE FLAG. `promote` writes `developmentOnly: false` only when the
# transcript carries enough distinct contributors, a closing beacon, and a passing verification
# after it, see scripts/v2/wf-ceremony-transcript.mjs, which also states what a transcript still
# cannot prove. There is no --force.
#
# ENTROPY IS NEVER AN ARGUMENT. `snarkjs zkey contribute` is run interactively so the participant
# types their entropy into a prompt: an argument lands in the shell history, the process table and
# every `ps` on the machine.
#
# The artifacts live under circuits/build/wf-production/ and do not touch the development bundle,
# so a ceremony in progress cannot break a lane that is running on the dev keys.

set -euo pipefail

# The pinned compiler, same as build.sh and repro-check.sh: bare `circom` fails on a fresh
# clone with "command not found", and an unpinned one compiles a different circuit.
# shellcheck source=scripts/v2/lib/fetch-circom.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/fetch-circom.sh"
CIRCOM="$(ensure_circom "${GAP_CIRCOM_CACHE:-}")" || exit 1
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

# WHERE THIS PARTICIPANT'S COPY OF THE CEREMONY LIVES.
#
# A real ceremony is not one directory: each contributor receives the previous zkeys, contributes
# ON THEIR OWN MACHINE, and hands the result on. `GAP_CEREMONY_DIR` is what makes that expressible
#: every participant points the harness at their own copy, and the chain is the sequence of
# copies rather than one shared folder somebody takes turns in.
#
# It defaults to the old path, so an existing single-operator run is unchanged.
BUILD="${GAP_CEREMONY_DIR:-$ROOT/circuits/build/wf-production}"
KEYS="$BUILD/keys"
TRANSCRIPT="$BUILD/transcript.json"
PINS="$BUILD/pins.json"

# PHASE-1 IS RECORDED PER CIRCUIT, AND IT IS ONE VERIFIED FILE. The session circuit is 59,143
# constraints, so it needs the 2^16. The well-formedness circuits would fit a 2^13 (the largest,
# wf_cred, is 4,783), but every upstream host for that file now returns 403 and upstream publishes
# no digest this repository could check it against. Phase 1 is universal, so a larger file is a
# valid phase-1 for a smaller circuit: every circuit uses the digest-verified 2^16, at the cost of a
# slower setup for the small ones. The transcript still records each circuit's phase-1 by name and
# sha256, so a later change to any one of them is visible.
PTAU_16="powersOfTau28_hez_final_16.ptau"

# name : source (relative to circuits/) : phase-1 file
#
# THE SESSION CIRCUITS ARE HERE NOW, and they are the reason this harness exists. Until they were
# added, the multi-contributor gate covered the three well-formedness circuits and NOT the one
# whose verifier gates every transfer: the promotion machinery was pointed at the circuits that
# matter least.
CIRCUITS=(
  "wf_salt_binding:src/v2/wf_salt_binding.circom:$PTAU_16"
  "wf_cred:src/v2/wf_cred.circom:$PTAU_16"
  "wf_pseudonym:src/v2/wf_pseudonym.circom:$PTAU_16"
  "session:src/v2/session.circom:$PTAU_16"
)
NAMES=(wf_salt_binding wf_cred wf_pseudonym session)

# The 2^16 pin lives in one place, shared with the dev build. See S-4: a ceremony over an
# unverified phase-1 file is worth nothing.
# shellcheck source=scripts/v2/lib/fetch-ptau.sh
. "$ROOT/scripts/v2/lib/fetch-ptau.sh"

# sha256 of a phase-1 file, for the transcript. The file is additionally verified against
# upstream's published blake2b by `ensure_ptau`.
phase1_sha256() {
  node -e '
    const { createHash } = require("node:crypto");
    const { createReadStream } = require("node:fs");
    const h = createHash("sha256");
    const s = createReadStream(process.argv[1]);
    s.on("data", (c) => h.update(c));
    s.on("end", () => process.stdout.write(h.digest("hex")));
  ' "$1"
}

fail() { echo "✗ $*" >&2; exit 1; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
snarkjs() { ( cd "$ROOT/circuits" && pnpm exec snarkjs "$@" ); }

# Every transcript mutation goes through the module that owns the rules, so the shell never
# decides what a valid ceremony is.
transcript_call() {
  node --input-type=module -e "
    import * as t from '$ROOT/scripts/v2/wf-ceremony-transcript.mjs';
    const path = '$TRANSCRIPT';
    $1
  "
}

require_transcript() {
  [ -f "$TRANSCRIPT" ] || fail "no ceremony in progress, run: $0 init"
}

case "${1:-status}" in

init)
  [ -f "$TRANSCRIPT" ] && fail "a ceremony is already open at $TRANSCRIPT (delete it to restart)"
  mkdir -p "$KEYS"
  ensure_ptau "$ROOT/$PTAU_16" || fail "phase-1 (2^16) could not be verified"
  echo "▸ compiling the ceremony circuits…"
  phase1_json="{"
  for entry in "${CIRCUITS[@]}"; do
    IFS=: read -r name source ptau <<<"$entry"
    ( cd "$ROOT/circuits" && "$CIRCOM" "$source" --r1cs --wasm --sym -o "$BUILD" -l node_modules >/dev/null )
    snarkjs groth16 setup "$BUILD/$name.r1cs" "$ROOT/$ptau" \
      "$KEYS/${name}_0000.zkey" >/dev/null
    sha="$(phase1_sha256 "$ROOT/$ptau")"
    phase1_json="$phase1_json\"$name\":{\"name\":\"$ptau\",\"sha256\":\"$sha\"},"
    echo "  $name → keys/${name}_0000.zkey   (phase-1 $ptau)"
  done
  phase1_json="${phase1_json%,}}"
  names_json="$(printf "'%s'," "${NAMES[@]}")"
  transcript_call "t.writeTranscript(path, t.emptyTranscript($phase1_json, [${names_json%,}]))"
  echo "✅ ceremony open. Each participant now runs, on THEIR OWN machine:"
  echo "     $0 contribute \"Their Name\""
  echo "   At least $(transcript_call "process.stdout.write(String(t.MINIMUM_CONTRIBUTIONS))") distinct people, then: $0 beacon <hex>"
  ;;

contribute)
  require_transcript
  PARTICIPANT="${2:-}"
  [ -n "$PARTICIPANT" ] || fail "usage: $0 contribute \"Their Name\""
  echo "▸ ${PARTICIPANT}'s contribution. snarkjs will PROMPT for entropy, type freely, and do not"
  echo "  paste anything you have used before or will reuse. Nothing you type is stored."
  for name in "${NAMES[@]}"; do
    LATEST=$(ls -1 "$KEYS/${name}_"[0-9]*.zkey 2>/dev/null | sort | tail -1)
    [ -n "$LATEST" ] || fail "$name has no zkey to contribute to, run: $0 init"
    NEXT=$(printf '%s/%s_%04d.zkey' "$KEYS" "$name" "$(( $(basename "$LATEST" | sed "s/${name}_//;s/\.zkey//" | sed 's/^0*//;s/^$/0/') + 1 ))")
    # Interactive on purpose: entropy typed at a prompt, never in argv.
    snarkjs zkey contribute "$KEYS/$(basename "$LATEST")" \
      "$KEYS/$(basename "$NEXT")" --name="$PARTICIPANT" \
      || fail "$name: contribution failed"
    HASH=$(shasum -a 256 "$NEXT" | cut -d' ' -f1)
    # Exported, not prefixed: `VAR=x func` is not reliably passed to a shell FUNCTION's children
    # the way it is for a command, and bash 3.2 is what macOS ships.
    export GAP_CEREMONY_PARTICIPANT="$PARTICIPANT"
    transcript_call "t.writeTranscript(path, t.recordContribution(t.readTranscript(path), { participant: process.env.GAP_CEREMONY_PARTICIPANT, circuit: '$name', contributionHash: '0x$HASH', at: '$(now)' }))" \
      || fail "$name: the transcript refused this contribution"
    echo "  $name ← $PARTICIPANT"
  done
  echo "✅ recorded. $0 status shows how many distinct parties have contributed."
  ;;

beacon)
  require_transcript
  RANDOMNESS="${2:-}"
  SOURCE="${3:-}"
  ITERATIONS="${4:-10}"
  [ -n "$SOURCE" ] || fail "usage: $0 beacon <public-randomness-hex> <source> [iterations]
  The SOURCE is published with the transcript and is what makes the randomness checkable, 
  'drand quicknet round 6389234', 'Bitcoin block 000000...'. Without it the hex is just a number."
  [ -n "$RANDOMNESS" ] || fail "usage: $0 beacon <public-randomness-hex> <source> [iterations]
  Use a value nobody can have chosen in advance and everyone can check afterwards: a future
  Bitcoin block hash, a drand round. Publish which one, alongside the transcript."
  for name in "${NAMES[@]}"; do
    LATEST=$(ls -1 "$KEYS/${name}_"[0-9]*.zkey | sort | tail -1)
    snarkjs zkey beacon "$KEYS/$(basename "$LATEST")" \
      "$KEYS/${name}_final.zkey" "$RANDOMNESS" "$ITERATIONS" \
      --name="closing beacon" >/dev/null || fail "$name: beacon failed"
    echo "  $name → keys/${name}_final.zkey"
  done
  export GAP_CEREMONY_BEACON_SOURCE="$SOURCE"
  transcript_call "t.writeTranscript(path, t.recordBeacon(t.readTranscript(path), { publicRandomness: '$RANDOMNESS', iterations: $ITERATIONS, source: process.env.GAP_CEREMONY_BEACON_SOURCE, at: '$(now)' }))"
  echo "✅ closed on public randomness. Next: $0 verify"
  ;;

verify)
  require_transcript
  for entry in "${CIRCUITS[@]}"; do
    IFS=: read -r name source ptau <<<"$entry"
    [ -f "$KEYS/${name}_final.zkey" ] || fail "$name has no final zkey, run: $0 beacon <hex>"
    # Verified against THIS circuit's phase-1 file, not a shared one.
    if snarkjs zkey verify "$BUILD/$name.r1cs" "$ROOT/$ptau" \
        "$KEYS/${name}_final.zkey" >/dev/null 2>&1; then
      PASSED=true; echo "  $name: verified"
    else
      PASSED=false; echo "  $name: VERIFICATION FAILED"
    fi
    snarkjs zkey export verificationkey "$KEYS/${name}_final.zkey" \
      "$KEYS/${name}_vkey.json" >/dev/null 2>&1 || true
    transcript_call "t.writeTranscript(path, t.recordVerification(t.readTranscript(path), { circuit: '$name', passed: $PASSED, at: '$(now)' }))"
  done
  echo "✅ recorded. Next: $0 promote"
  ;;

promote)
  require_transcript
  # The guard lives in the module and throws with the specific unmet condition. There is no
  # --force: an operator who could override it is an operator who can flip developmentOnly.
  transcript_call "
    const transcript = t.readTranscript(path);
    let header;
    // The refusal is the feature, so it is REPORTED, not thrown at an operator as a stack trace.
    try { header = t.productionPinsHeader(transcript); }
    catch (error) { process.stderr.write(error.message + '\\n'); process.exit(1); }
    const { writeFileSync } = await import('node:fs');
    const circuits = {};
    for (const name of transcript.circuits) {
      circuits[name] = {
        zkey: 'keys/' + name + '_final.zkey',
        verificationKey: 'keys/' + name + '_vkey.json',
        r1cs: name + '.r1cs',
      };
    }
    writeFileSync('$PINS', JSON.stringify({ schemaVersion: 1, ...header, circuits }, null, 2) + '\n');
    process.stdout.write('promoted: ' + header.contributors.join(', ') + '\n');
  " || fail "promotion refused: the transcript says why, above"
  echo "✅ production pins written to $PINS (developmentOnly: false)."
  echo "   PUBLISH $TRANSCRIPT alongside them. A transcript nobody can read is not a ceremony"
  echo "   anyone can audit, and auditability is the whole reason this was multi-party."
  ;;

status)
  [ -f "$TRANSCRIPT" ] || { echo "no ceremony in progress. Start one: $0 init"; exit 0; }
  transcript_call "
    const transcript = t.readTranscript(path);
    for (const circuit of transcript.circuits) {
      const parties = [...t.participantsFor(transcript, circuit)];
      process.stdout.write(circuit.padEnd(18) + parties.length + '/' + t.MINIMUM_CONTRIBUTIONS
        + ' parties' + (parties.length ? ' (' + parties.join(', ') + ')' : '') + '\n');
    }
    process.stdout.write('beacon' .padEnd(18) + (transcript.beacon ? 'closed' : 'NOT CLOSED') + '\n');
    try { t.assertPromotable(transcript); process.stdout.write('\nready to promote\n'); }
    catch (error) { process.stdout.write('\n' + error.message + '\n'); }
  "
  ;;

*) fail "usage: $0 [init|contribute <name>|beacon <hex> [iters]|verify|promote|status]" ;;
esac
