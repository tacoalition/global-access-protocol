#!/usr/bin/env bash
#
# THE GOLDEN PATH. One command, from a cold clone to the whole story, repeatable.
#
# WHAT THIS ENDS. `make demo` used to need `make up` run first, and `make dex-up` run between them for
# the pool beats, and a second `make demo` on the same chain stopped at `DID: exists`, because the
# story onboards a fixed identity and the registry correctly refuses a duplicate. All three are
# reasonable behaviours and none of them belongs in a reader's first five minutes. A golden path that
# needs a warning is not a golden path.
#
# So this does every prerequisite itself, and always starts from a fresh chain. Running it twice is
# the same as running it once. The step-by-step route is still there for anyone who wants it:
# `make up`, then `make cli ARGS=onboard`, `session`, `transfer 100`, `flag`.
set -euo pipefail
cd "$(dirname "$0")/../.."

step() { printf "\n\033[1m▸ %s\033[0m\n" "$1"; }

# 0. DEPENDENCIES. The circuit compiles with `-l node_modules` for circomlib, so without this the
#    very first command in a fresh clone dies on "circomlib/circuits/poseidon.circom ... not found".
#    A review caught this: the golden path claimed to work from a cold clone and had never been run
#    from one: every test of it had installed dependencies as a separate step first.
# pnpm installs circomlib into the circuits package, not the root, so that is the path to test.
if [ ! -d node_modules ] || [ ! -d circuits/node_modules/circomlib ]; then
  step "Installing dependencies"
  pnpm install --frozen-lockfile
fi

# 1. PROVING ARTIFACTS. Not shipped, `build.sh` makes them from the committed circuit, which is the
#    point: what you prove with is what this repository describes. First run only, and it is slow
#    enough that saying so beats looking hung.
if [ ! -f circuits/keys/v2/session_final.zkey ] || [ ! -f circuits/build/v2/session_js/session.wasm ]; then
  step "First run: building the circuit and proving key (a few minutes, once)"
  echo "   fetching circom and a 72 MB powers-of-tau file, compiling 59k constraints,"
  echo "   running the local setup, and emitting the Solidity verifier."
  bash scripts/v2/build.sh
else
  step "Proving artifacts present, skipping the build"
  echo "   run 'make build' yourself if you changed the circuit."
fi

# 2. A FRESH CHAIN, every time. This is what makes the command repeatable: the story's identity is
#    fixed, so it needs a registry that has not seen it.
step "Starting a fresh local chain and deploying the stack"
bash scripts/v2/spinup.sh >/dev/null
echo "   ✓ contracts deployed → contracts/deployments/31337-v2.json"

# 3. THE POOL. Additive on purpose: the token story stands without it, but the golden path shows
#    everything, so it goes in before the story rather than being a step the reader has to know about.
step "Adding the permissioned AMM"
set -a; . ./.env.anvil; set +a
export USER_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# shellcheck source=scripts/v2/lib/broadcast.sh
. scripts/v2/lib/broadcast.sh
broadcast deploy-dex script/v2/DeployDexV2.s.sol:DeployDexV2 --rpc-url "$RPC_URL"
echo "   ✓ pool live → contracts/deployments/31337-dex.json"

# 4. THE STORY. The two acknowledgements are set here for the same reason the Makefile sets them:
#    both are refusals the system makes on purpose, and the demo states them rather than pretending
#    the gates were satisfied.
step "Running the story"
cd packages/gap-cli
GAP_DEMO_ALLOW_PUBLIC_SALT=1 GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1 npx tsx src/cli.ts demo

cat <<'NEXT'

─────────────────────────────────────────────────────────────────────
That was the whole story. The chain is still up, so you can poke at it:

  make cli ARGS=status        what the chain knows about the holder
  make disclosure             what it saw, and what it never saw
  make policy-floor           a one-person predicate refused at registration
  make pool-story             just the permissioned-AMM act

  make test                   contracts + packages, incl. a real proof on-chain
  make repro                  the verifier rebuilds byte-for-byte from source

  make demo                   run all of this again, from a fresh chain
  make down                   stop the chain
─────────────────────────────────────────────────────────────────────
NEXT
