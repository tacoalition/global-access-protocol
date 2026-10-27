#!/usr/bin/env bash
#
# FETCH THE PHASE-1 POWERS-OF-TAU, AND REFUSE ANYTHING THAT IS NOT IT.
#
# WHAT THIS ENDS. Both build scripts fetched the ptau with `curl -sL`: no `-f`, so an HTTP error
# page is written to disk AS THE PTAU and the next step consumes it; and no digest, so a
# substituted file is indistinguishable from the real one. A phase-2 ceremony with three
# contributors and a closing beacon over a substituted phase-1 file is worth exactly nothing: the
# trapdoor everyone contributed to destroying was never the one in play.
#
# THE PIN IS UPSTREAM'S OWN, NOT OURS. `PTAU_BLAKE2B` below is the value the snarkjs README
# publishes for this file, and the local copy was verified to match it before it was written down.
# That is the provenance link: not "the bytes I happened to have", but "the bytes iden3 says these
# are". sha256 is verified alongside it because it is the cheap, universally available check;
# blake2b is the one that ties to upstream.
#
# ON MISMATCH THE FILE IS DELETED, not left in place. A rejected artifact that stays on disk is one
# a later run finds present and skips re-fetching: the failure would launder itself into a pass.
set -euo pipefail

# SEVERAL SOURCES, TRIED IN ORDER, BECAUSE UPSTREAM'S ARE GONE. Checked 2026-09-28: the Google
# Storage bucket, the Hermez S3 bucket and the PSE bucket ALL return HTTP 403. A pinned URL that
# 403s is a repository nobody can build from, so the first entry is a verbatim mirror published as
# a release asset on this repository.
#
# MIRRORING IS SAFE HERE ONLY BECAUSE OF THE DIGESTS BELOW. They are upstream's own published
# values, and `verify_ptau` refuses the file unless BOTH match, so a mirror is checked, never
# trusted. Add sources freely; do not touch the digests.
# An ARRAY, not a space-separated string: an unquoted string does not word-split in zsh, so a
# developer sourcing this interactively on macOS would silently try only the FIRST source and
# report that every source failed. Arrays behave identically in bash and zsh.
PTAU_URLS=(
  "https://github.com/tacoalition/global-access-protocol/releases/download/ptau-hez-16/powersOfTau28_hez_final_16.ptau"
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau"
  "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau"
)
# Published: https://github.com/iden3/snarkjs#7-prepare-phase-2 (2^16 row)
PTAU_BLAKE2B="6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125"
PTAU_SHA256="1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922"

# Node rather than shasum/b2sum: node is already required by every caller, and blake2b has no
# portable coreutils spelling across macOS and Linux.
ptau_digests() {
  node -e '
    const { createHash } = require("node:crypto");
    const { createReadStream } = require("node:fs");
    const path = process.argv[1];
    const b2 = createHash("blake2b512");
    const s2 = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => { b2.update(chunk); s2.update(chunk); });
    stream.on("error", () => { process.exit(2); });
    stream.on("end", () => {
      process.stdout.write(`${b2.digest("hex")} ${s2.digest("hex")}`);
    });
  ' "$1"
}

verify_ptau() {
  local path="$1" label="${2:-powers-of-tau}"
  local digests blake sha
  digests="$(ptau_digests "$path")" || {
    echo "$label: could not be read for verification" >&2; return 1;
  }
  blake="${digests%% *}"; sha="${digests##* }"
  if [ "$blake" != "$PTAU_BLAKE2B" ] || [ "$sha" != "$PTAU_SHA256" ]; then
    echo "$label: digest mismatch: this is NOT the published phase-1 file. Deleting." >&2
    rm -f "$path"
    return 1
  fi
  return 0
}

# Fetch when absent, then verify ALWAYS, including a copy that was already on disk, which is the
# case a download-time-only check would never look at.
ensure_ptau() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "▸ fetching powers-of-tau (2^16)…"
    ok=0
    # WHILE THIS REPOSITORY IS PRIVATE, its own release asset 404s for an anonymous curl, release
    # downloads carry the repository's visibility. `gh` is already authenticated for anyone who can
    # clone a private repo, so it is tried first and simply fails through when gh is absent. Once
    # the repository is public the plain URL below serves it and this step becomes redundant.
    if [ "$ok" -ne 1 ] && command -v gh >/dev/null 2>&1; then
      if gh release download ptau-hez-16 \
           --repo tacoalition/global-access-protocol \
           --pattern "powersOfTau28_hez_final_16.ptau" \
           --output "$path" --clobber >/dev/null 2>&1; then
        ok=1
      else
        rm -f "$path"
      fi
    fi
    for url in "${PTAU_URLS[@]}"; do
      [ "$ok" -eq 1 ] && break
      # -f so an HTTP error page is an error rather than a 4 KB file written AS THE PTAU.
      if curl -fsSL -o "$path" "$url"; then ok=1; break; fi
      rm -f "$path"
      echo "  that source did not serve it; trying the next" >&2
    done
    if [ "$ok" -ne 1 ]; then
      echo "powers-of-tau download failed from every source:" >&2
      for url in "${PTAU_URLS[@]}"; do echo "  $url" >&2; done
      echo "Fetch it yourself and put it at $path: the digest check below will confirm it." >&2
      return 1
    fi
  fi
  verify_ptau "$path" "powers-of-tau (2^16)"
}
