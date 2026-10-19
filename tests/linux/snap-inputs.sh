#!/usr/bin/env bash
# The only store-dependent step. The harness consumes these files offline.
set -euo pipefail

mode=${1:?usage: snap-inputs.sh fetch-or-verify cache-directory}
cache=${2:?missing cache directory}
pins=$(realpath "$(dirname "$0")/suite/snap-inputs.json")
arch=$(dpkg --print-architecture)
mkdir -p "$cache"
cd "$cache"

for name in snapd core24; do
  revision=$(jq -er --arg arch "$arch" --arg name "$name" '.[$arch][$name].revision | select(test("^[0-9]+$"))' "$pins")
  sha256=$(jq -er --arg arch "$arch" --arg name "$name" '.[$arch][$name].sha256 | select(test("^[a-f0-9]{64}$"))' "$pins")

  case "$mode" in
    fetch)
      downloaded=false
      for attempt in 1 2 3; do
        echo "Downloading $name revision $revision ($arch), attempt $attempt/3 (180s limit)"
        if timeout --kill-after=10s 180s snap download "$name" --revision="$revision"; then
          downloaded=true
          break
        fi
        if (( attempt < 3 )); then
          sleep "$((attempt * 5))"
        fi
      done
      if [[ $downloaded != true ]]; then
        echo "::error::$name revision $revision ($arch): Snap Store download failed after 3 bounded attempts; the required snap identity case cannot be provisioned."
        exit 1
      fi
      ;;
    verify) ;;
    *) echo "Unknown mode: $mode" >&2; exit 1 ;;
  esac

  test -s "${name}_${revision}.assert" || {
    echo "::error::Missing $name assertion for revision $revision ($arch); refusing an unsigned prerequisite."
    exit 1
  }
  if ! printf '%s  %s\n' "$sha256" "${name}_${revision}.snap" | sha256sum --check --strict; then
    echo "::error::$name revision $revision ($arch): cached/downloaded snap does not match pinned SHA-256 $sha256."
    exit 1
  fi
  echo "$name: arch=$arch revision=$revision SHA-256=$sha256 (verified)"
done
