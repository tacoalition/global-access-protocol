#!/usr/bin/env bash
# Stop only the Anvil process recorded by the GAP v2 launcher.
set -euo pipefail

DEFAULT_PID_FILE="${TMPDIR:-/tmp}/gap-v2-anvil-$(id -u).pid"
PID_FILE="${GAP_ANVIL_PID_FILE:-$DEFAULT_PID_FILE}"

if [ ! -e "$PID_FILE" ]; then
  echo "  no GAP v2-owned anvil is recorded at $PID_FILE"
  exit 0
fi
if [ -L "$PID_FILE" ] || [ ! -f "$PID_FILE" ]; then
  echo "refusing unsafe GAP Anvil PID file: $PID_FILE" >&2
  exit 1
fi

PID="$(sed -n '1p' "$PID_FILE")"
RECORDED_START="$(sed -n '2p' "$PID_FILE")"
RECORDED_COMMAND="$(sed -n '3p' "$PID_FILE")"
if ! [[ "$PID" =~ ^[1-9][0-9]*$ ]] || [ -z "$RECORDED_START" ] || [ -z "$RECORDED_COMMAND" ]; then
  echo "refusing malformed GAP Anvil PID file: $PID_FILE" >&2
  exit 1
fi

process_is_running() {
  if ! kill -0 "$1" 2>/dev/null; then
    return 1
  fi
  local state
  state="$(ps -ww -p "$1" -o stat= 2>/dev/null || true)"
  [[ "$state" != *Z* ]]
}

if ! process_is_running "$PID"; then
  rm -f "$PID_FILE"
  echo "  removed stale GAP v2 Anvil PID file"
  exit 0
fi

CURRENT_START="$(ps -ww -p "$PID" -o lstart= 2>/dev/null || true)"
CURRENT_COMMAND="$(ps -ww -p "$PID" -o command= 2>/dev/null || true)"
if [ "$CURRENT_START" != "$RECORDED_START" ] \
  || [ "$CURRENT_COMMAND" != "$RECORDED_COMMAND" ] \
  || [[ "$CURRENT_COMMAND" != *anvil* ]]; then
  echo "refusing to stop PID $PID: it is not the GAP v2-owned Anvil process" >&2
  exit 1
fi

kill -TERM "$PID"
for _ in $(seq 1 50); do
  if ! process_is_running "$PID"; then
    rm -f "$PID_FILE"
    echo "  stopped GAP v2-owned anvil (PID $PID)"
    exit 0
  fi
  sleep 0.1
done

kill -KILL "$PID" 2>/dev/null || true
for _ in $(seq 1 20); do
  if ! process_is_running "$PID"; then
    rm -f "$PID_FILE"
    echo "  force-stopped GAP v2-owned anvil (PID $PID)"
    exit 0
  fi
  sleep 0.1
done

echo "GAP v2-owned Anvil PID $PID did not stop; retaining $PID_FILE" >&2
exit 1
