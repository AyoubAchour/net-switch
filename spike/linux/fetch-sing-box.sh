#!/usr/bin/env bash
# Downloads the plain sing-box Linux build for this machine and checks it
# against the SHA-256 pinned in the workflow before anything runs it.
set -euo pipefail
version=${SING_BOX_VERSION:?}
case "$(uname -m)" in
  x86_64) arch=amd64 sum=${SING_BOX_SHA256_AMD64:?} ;;
  aarch64) arch=arm64 sum=${SING_BOX_SHA256_ARM64:?} ;;
  *)
    echo "unsupported machine $(uname -m)"
    exit 1
    ;;
esac
name="sing-box-$version-linux-$arch"
dir=$(mktemp -d)
curl -fsSL --retry 3 -o "$dir/$name.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v$version/$name.tar.gz"
echo "$sum  $dir/$name.tar.gz" | sha256sum -c -
echo "Archive contents:"
tar -tzvf "$dir/$name.tar.gz"
sudo mkdir -p /opt/sing-box
sudo tar -xzf "$dir/$name.tar.gz" -C /opt/sing-box --strip-components=1
/opt/sing-box/sing-box version
