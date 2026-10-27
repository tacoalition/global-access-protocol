#!/usr/bin/env bash
# GAP v2: one command to stand up the whole stack on a fresh local Anvil chain.
# Deploys Poseidon2, then the full v2 topology + demo scenario. Idempotent restart.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
RPC="${RPC_URL:-http://127.0.0.1:8545}"
DEFAULT_PID_FILE="${TMPDIR:-/tmp}/gap-v2-anvil-$(id -u).pid"
# Joined launchers can set GAP_ANVIL_PID_FILE to own an isolated local chain.
ANVIL_PID_FILE="${GAP_ANVIL_PID_FILE:-$DEFAULT_PID_FILE}"
ANVIL_LOG_FILE="${GAP_ANVIL_LOG_FILE:-${TMPDIR:-/tmp}/gap-v2-anvil-$(id -u).log}"
read -r RPC_HOST RPC_PORT < <(node -e '
  const url = new URL(process.argv[1]);
  console.log(url.hostname, url.port || "8545");
' "$RPC")
case "$RPC_HOST" in
  127.0.0.1|localhost|\[::1\]) ;;
  *) echo "refusing to launch local Anvil for non-loopback RPC host: $RPC_HOST" >&2; exit 1 ;;
esac
ANVIL_HOST="${RPC_HOST#[}"
ANVIL_HOST="${ANVIL_HOST%]}"
set -a; source .env.anvil; set +a   # export env so forge (vm.envUint) can read PRIVATE_KEY
# The gap CLI's user is Anvil account #1; force it (override any USER_ADDRESS from .env.anvil)
# so the demo mint lands on the account the CLI actually drives.
export USER_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

echo "▸ checking local proof artifact coherence…"
node scripts/v2/check-artifacts.mjs

echo "▸ (re)starting anvil…"
GAP_ANVIL_PID_FILE="$ANVIL_PID_FILE" bash scripts/v2/anvil-stop.sh
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "refusing to replace an unowned RPC process already listening at $RPC" >&2
  exit 1
fi
mkdir -p "$(dirname "$ANVIL_PID_FILE")" "$(dirname "$ANVIL_LOG_FILE")"
umask 077
anvil --silent --host "$ANVIL_HOST" --port "$RPC_PORT" --chain-id 31337 \
  > "$ANVIL_LOG_FILE" 2>&1 &
ANVIL_PID=$!
KEEP_ANVIL=0
RECORDED_ANVIL=0
cleanup() {
  status=$?
  trap - EXIT
  if [ "$KEEP_ANVIL" -ne 1 ]; then
    if [ "$RECORDED_ANVIL" -eq 1 ]; then
      GAP_ANVIL_PID_FILE="$ANVIL_PID_FILE" bash scripts/v2/anvil-stop.sh || true
    elif kill -0 "$ANVIL_PID" 2>/dev/null; then
      kill -TERM "$ANVIL_PID" 2>/dev/null || true
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sleep 0.1
if ! kill -0 "$ANVIL_PID" 2>/dev/null; then
  echo "Anvil failed to start; see $ANVIL_LOG_FILE" >&2
  exit 1
fi
ANVIL_START="$(ps -ww -p "$ANVIL_PID" -o lstart=)"
ANVIL_COMMAND="$(ps -ww -p "$ANVIL_PID" -o command=)"
PID_TMP="${ANVIL_PID_FILE}.tmp.$$"
printf '%s\n%s\n%s\n' "$ANVIL_PID" "$ANVIL_START" "$ANVIL_COMMAND" > "$PID_TMP"
mv -f "$PID_TMP" "$ANVIL_PID_FILE"
RECORDED_ANVIL=1

ANVIL_READY=0
for _ in $(seq 1 20); do
  if ! kill -0 "$ANVIL_PID" 2>/dev/null; then
    echo "Anvil exited during startup; see $ANVIL_LOG_FILE" >&2
    exit 1
  fi
  if [ "$(cast chain-id --rpc-url "$RPC" 2>/dev/null || true)" = "31337" ]; then
    ANVIL_READY=1
    break
  fi
  sleep 0.5
done
if [ "$ANVIL_READY" -ne 1 ]; then
  echo "Anvil did not become ready on $RPC with chain ID 31337" >&2
  exit 1
fi
echo "  anvil up on $RPC (chain 31337)"

echo "▸ deploying Poseidon2 (circuit-compatible hasher)…"
POSEIDON=$(cast send --private-key "$PRIVATE_KEY" --rpc-url "$RPC" --create \
  "$(tail -1 contracts/bytecode/Poseidon2.bytecode)" --json | python3 -c "import sys,json;print(json.load(sys.stdin)['contractAddress'])")
mkdir -p contracts/deployments
echo "{\"poseidon2\": \"$POSEIDON\"}" > contracts/deployments/31337-poseidon.json
echo "  Poseidon2: $POSEIDON"

echo "▸ deploying GAP v2 topology + demo scenario…"
# shellcheck source=scripts/v2/lib/broadcast.sh
. "$ROOT/scripts/v2/lib/broadcast.sh"
broadcast deploy-v2 script/v2/DeployV2.s.sol:DeployV2 --rpc-url "$RPC" || exit 1
echo "  done → contracts/deployments/31337-v2.json"
echo ""
echo "✅ GAP v2 stack is live. Interact with it:"
echo "     make cli ARGS=status"
echo "     make cli ARGS=onboard"
echo "     make cli ARGS=session"
echo "     make cli ARGS='transfer 100'"
echo "     make cli ARGS=flag"
echo "   or the whole story in one shot:  make demo"
KEEP_ANVIL=1
