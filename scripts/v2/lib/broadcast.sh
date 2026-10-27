# shellcheck shell=bash
# Run one `forge script --broadcast` against the local chain, with a log and a time limit.
#
#   broadcast <name> <forge script args…>     run from the repository root
#
# WHY THIS EXISTS. The deploys used to run with their output sent to /dev/null and no time limit.
# One cold run in five, Anvil left the deploy's transactions queued and unmined and forge waited on
# them forever, so `make demo` sat on "Starting a fresh local chain" with nothing to say why.
#
#   --slow       sends each transaction only after the previous one is mined, which is what stops
#                Anvil queueing a burst of them in the first place;
#   the log      goes to contracts/broadcast/<name>.log (gitignored, beside forge's own records),
#                and its tail is printed on any failure;
#   the limit    is GAP_DEPLOY_TIMEOUT seconds (default 300, against about 20 measured), after which
#                the deploy is killed and reported rather than waited on.
broadcast() {
  local name="$1"; shift
  local log="contracts/broadcast/$name.log"
  local limit="${GAP_DEPLOY_TIMEOUT:-300}"
  mkdir -p contracts/broadcast
  ( cd contracts && exec forge script "$@" --broadcast --slow ) >"$log" 2>&1 &
  local pid=$! waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      echo "✗ $name did not finish in ${limit}s (GAP_DEPLOY_TIMEOUT). Last lines of $log:" >&2
      tail -20 "$log" >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if ! wait "$pid"; then
    echo "✗ $name failed. Last lines of $log:" >&2
    tail -20 "$log" >&2
    return 1
  fi
}
