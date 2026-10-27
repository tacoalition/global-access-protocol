#!/usr/bin/env bash
#
# PIN THE COMPILER, BECAUSE THE COMPILER IS AN INPUT.
#
# `make repro` claims the committed verifier rebuilds byte-for-byte from the committed circuit.
# That claim is only meaningful against a NAMED compiler: circom is what turns source into the
# r1cs everything downstream is derived from, and two circom versions can compile one circuit into
# two different constraint systems. A CI runner that installs "latest circom" turns the gate into a
# coin flip: it fails on an upstream release, for a reason that has nothing to do with the change
# under review, and the usual response to that is to switch the gate off.
#
# So the version is pinned here, the binary is verified by digest, and the manifest records what
# actually built the artifacts. `scripts/v2/setup-determinism.test.mjs` fails if this pin and the
# manifest ever disagree.
#
# WHY A PUBLISHED BINARY AND NOT `cargo install`. A source build is several minutes per CI run and
# is NOT reproducible across Rust toolchains, so it would pin nothing while costing the most. The
# digests below are of iden3's own release assets, taken from the v2.2.2 tag.
#
# ON MISMATCH THE FILE IS DELETED. A rejected binary left on disk is one the next run finds present
# and skips re-fetching: the failure would launder itself into a pass.
set -euo pipefail

CIRCOM_VERSION="2.2.2"
CIRCOM_RELEASE="https://github.com/iden3/circom/releases/download/v${CIRCOM_VERSION}"
# sha256 of iden3's published release assets for this tag.
CIRCOM_SHA256_linux_x86_64="f3d8d1fdbc123779b80e210c909ee941d7a1e130c70365524646b48b8b0fe9d5"
CIRCOM_SHA256_darwin_x86_64="415022bdb948cff8dffd119d063809e1cfe2cc38b76c03da748673c87cffd239"

circom_asset() {
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)  echo "circom-linux-amd64 $CIRCOM_SHA256_linux_x86_64" ;;
    # iden3 publishes no arm64 asset. On Apple Silicon the x86_64 build runs under Rosetta and
    # reports the pinned version, which is verified below, so the most common developer machine
    # gets the pinned compiler rather than a refusal.
    Darwin/x86_64|Darwin/arm64) echo "circom-macos-amd64 $CIRCOM_SHA256_darwin_x86_64" ;;
    *)
      # Linux/aarch64 and anything else: refuse, rather than silently falling through to whatever
      # circom is on PATH. An unpinned compiler in a reproducibility gate is the whole failure.
      echo "" ;;
  esac
}

circom_digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Prints the path to a circom that IS the pinned version, or fails. An already-installed circom of
# the right version is used as-is: pinning is about which compiler runs, not about where it lives.
ensure_circom() {
  local cache="${1:-}"
  [ -n "$cache" ] || cache="${TMPDIR:-/tmp}/gap-circom"
  if command -v circom >/dev/null 2>&1 &&
     [ "$(circom --version 2>/dev/null)" = "circom compiler $CIRCOM_VERSION" ]; then
    command -v circom
    return 0
  fi

  local asset expected entry
  entry="$(circom_asset)"
  if [ -z "$entry" ]; then
    echo "no pinned circom $CIRCOM_VERSION binary is published for $(uname -s)/$(uname -m); " \
         "install circom $CIRCOM_VERSION yourself: the reproducibility gate needs that exact " \
         "compiler and will not run against another" >&2
    return 1
  fi
  asset="${entry%% *}"; expected="${entry##* }"

  local binary="$cache/circom-$CIRCOM_VERSION"
  mkdir -p "$cache"
  if [ ! -x "$binary" ]; then
    curl -fsSL -o "$binary" "$CIRCOM_RELEASE/$asset" || {
      rm -f "$binary"
      echo "circom download failed (curl -f: a 4xx/5xx is an error, not a binary)" >&2
      return 1
    }
    chmod +x "$binary"
  fi

  local actual
  actual="$(circom_digest "$binary")"
  if [ "$actual" != "$expected" ]; then
    echo "circom $CIRCOM_VERSION digest mismatch: this is NOT the published binary. Deleting." >&2
    rm -f "$binary"
    return 1
  fi
  # Belt and braces: a digest match already implies the version, but the manifest is checked
  # against what the binary REPORTS, so confirm the two agree before anything depends on it.
  if [ "$("$binary" --version 2>/dev/null)" != "circom compiler $CIRCOM_VERSION" ]; then
    echo "the pinned circom binary does not report $CIRCOM_VERSION. Deleting." >&2
    rm -f "$binary"
    return 1
  fi
  echo "$binary"
}
