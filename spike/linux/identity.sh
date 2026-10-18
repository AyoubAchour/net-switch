#!/usr/bin/env bash
# Check 12: which path sing-box reports for different kinds of Linux apps, and
# whether path rules still match them. A local proxy (sing-box mixed inbound on
# 127.0.0.1) in the runner's own namespace, no TUN: process lookup works the
# same for local proxy connections, and snap and Flatpak apps run as they
# normally would. Needs root.
set -uo pipefail
# shellcheck source=spike/linux/lib.sh
source "$(dirname "$0")/lib.sh"

CLIENT="$HERE/client.mjs"
ANALYZE="$HERE/analyze.mjs"
PROXY=http://127.0.0.1:2080
SLOW="http://127.0.0.1:8090/slow?ms=2500"
API_PORT=9091
DIR="$OUT/check12"
mkdir -p "$DIR" && chmod 777 "$DIR"

# Pinned helpers for the AppImage case (SHA-256 from the GitHub release assets).
APPIMAGETOOL_URL=https://github.com/AppImage/appimagetool/releases/download/1.9.1
RUNTIME_URL=https://github.com/AppImage/type2-runtime/releases/download/20251108
case "$(uname -m)" in
  x86_64)
    APPIMAGE_ARCH=x86_64
    APPIMAGETOOL_SHA=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
    RUNTIME_SHA=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
    ;;
  aarch64)
    APPIMAGE_ARCH=aarch64
    APPIMAGETOOL_SHA=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
    RUNTIME_SHA=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
    ;;
esac

as_user() { setpriv --reuid="$APP_UID" --regid="$APP_GID" --init-groups env HOME="$APP_HOME" USER="$(id -un "$APP_UID")" "$@"; }

# observe LABEL PID: while the client PID holds its proxied request open, read
# the engine's connections to the test server and report the one it made.
observe() {
  local label=$1 pid=$2 conns="" i
  for i in $(seq 40); do
    sleep 0.15
    conns=$(api root /connections | "$NODE" "$ANALYZE" conns --dest-port 8090)
    grep -q processPath <<< "$conns" && break
  done
  wait "$pid" 2>/dev/null
  if grep -q processPath <<< "$conns"; then
    note "$label: \`$(head -1 <<< "$conns" | sed -E 's/^.* processPath=//')\`"
  else
    fail "$label: the engine never showed its connection (client said: $(tail -2 "$DIR/$label.out" 2>/dev/null | tr '\n' ' '))"
  fi
  printf '%s\n' "$conns" > "$DIR/$label.conns"
}

# Shows a running process the way the plan wants to identify it.
describe_pid() {
  local label=$1 pid=$2
  [ -n "$pid" ] && [ -e "/proc/$pid" ] || return
  info "$label: pid $pid exe=$(readlink "/proc/$pid/exe") cgroup=$(tr '\n' ' ' < "/proc/$pid/cgroup")"
  if [ -e "/proc/$pid/root/.flatpak-info" ]; then
    note "$label: /proc/$pid/root/.flatpak-info exists: $(grep -E '^(name|runtime)=' "/proc/$pid/root/.flatpak-info" | paste -sd ' ' -)"
  fi
}

# deleted_case LABEL APP ACTION: a node copy that loses its binary while running.
deleted_case() {
  local label=$1 app=$2 action=$3 trigger="$DIR/go-$2"
  rm -f "$trigger"
  as_user "/opt/nsapps/$app/node" "$CLIENT" proxied --proxy 127.0.0.1:2080 --url "$SLOW" --wait-file "$trigger" > "$DIR/$label.out" 2>&1 &
  local pid=$!
  sleep 0.7
  case "$action" in
    rm) rm -f "/opt/nsapps/$app/node" ;;
    replace) cp "$(readlink -f "$NODE")" "/opt/nsapps/$app/node.new" && mv -f "/opt/nsapps/$app/node.new" "/opt/nsapps/$app/node" ;;
  esac
  local node_pid
  node_pid=$(pgrep -n -f "/opt/nsapps/$app/node")
  info "$label: /proc/$node_pid/exe -> $(readlink "/proc/$node_pid/exe")"
  touch "$trigger"
  observe "$label" "$pid"
}

begin check12 "App identity: the path sing-box reports, and whether rules match"
for app in alpha delta epsilon zeta; do mkdir -p "/opt/nsapps/$app"; done
cp /usr/bin/curl /opt/nsapps/alpha/curl
for app in delta epsilon zeta; do cp "$(readlink -f "$NODE")" "/opt/nsapps/$app/node"; done
chmod -R a+rX /opt/nsapps

"$NODE" "$HERE/server.mjs" --host 127.0.0.1 --http-port 8090 --http-only > "$DIR/server.log" 2>&1 &
SERVER_PID=$!
wait_for "the local test server" 15 grep -q ready "$DIR/server.log" || exit 0
"$NODE" "$HERE/config.mjs" --out "$DIR" --identity
engine_start "$DIR" root || exit 0
summary "Rules: delta/epsilon exact path -> strict; zeta path with optional ' (deleted)' -> tolerant; python3 -> python; /snap/ -> snap; AppImage mounts -> appimage; /app/ or /usr/bin/curl -> usr-or-app; /opt/nsapps/alpha/ -> alpha; anything else -> other. The chain shows which matched."
summary ""

as_user /opt/nsapps/alpha/curl -s -x "$PROXY" "$SLOW" > "$DIR/alpha-curl.out" 2>&1 &
observe alpha-curl $!
/opt/nsapps/alpha/curl -s -x "$PROXY" "$SLOW" > "$DIR/alpha-curl-root.out" 2>&1 &
observe alpha-curl-as-root $!
as_user /usr/bin/curl -s -x "$PROXY" "$SLOW" > "$DIR/host-curl.out" 2>&1 &
observe host-usr-bin-curl $!

deleted_case deleted-strict-rule delta rm
deleted_case replaced-strict-rule epsilon replace
deleted_case deleted-tolerant-rule zeta rm

printf '%s\n' 'import sys, urllib.request' \
  'opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": sys.argv[1]}))' \
  'print(opener.open(sys.argv[2], timeout=10).read().decode().strip())' > "$DIR/client.py"
chmod a+r "$DIR/client.py"
as_user python3 "$DIR/client.py" "$PROXY" "$SLOW" > "$DIR/python3-script.out" 2>&1 &
observe python3-script $!

# Snap: a strictly confined curl from the Snap Store.
if command -v snap > /dev/null && timeout 300 snap install curl > "$DIR/snap-install.log" 2>&1; then
  info "snap: $(snap list curl 2>&1 | tail -1)"
  as_user /snap/bin/curl -s -x "$PROXY" "$SLOW" > "$DIR/snap-curl.out" 2>&1 &
  pid=$!
  sleep 1
  describe_pid snap-curl "$(pgrep -n -x curl)"
  observe snap-curl "$pid"
else
  note "snap: not possible here: $(command -v snap > /dev/null && tail -3 "$DIR/snap-install.log" | tr '\n' ' ' || echo 'snapd is not installed')"
fi

# Flatpak: curl from the freedesktop runtime, run in its sandbox.
flatpak_ok=
if timeout 300 apt-get install -y -q flatpak > "$DIR/flatpak-install.log" 2>&1 &&
  flatpak remote-add --system --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo >> "$DIR/flatpak-install.log" 2>&1; then
  for branch in 25.08 24.08; do
    if timeout 900 flatpak install --system -y --noninteractive flathub "org.freedesktop.Platform//$branch" >> "$DIR/flatpak-install.log" 2>&1; then
      flatpak_ok=$branch
      break
    fi
  done
fi
if [ -n "$flatpak_ok" ]; then
  runtime="org.freedesktop.Platform//$flatpak_ok"
  probe=$(as_user flatpak run --share=network --command=sh "$runtime" -c 'command -v curl; command -v python3' 2>&1)
  if ! grep -q curl <<< "$probe" && grep -qi 'userns\|namespace\|permission' <<< "$probe"; then
    info "flatpak run failed ($probe); allowing unprivileged user namespaces and retrying"
    sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0
    probe=$(as_user flatpak run --share=network --command=sh "$runtime" -c 'command -v curl; command -v python3' 2>&1)
  fi
  info "flatpak $runtime has: $(tr '\n' ' ' <<< "$probe")"
  if grep -q '/curl' <<< "$probe"; then
    as_user flatpak run --share=network --command=curl "$runtime" -s -x "$PROXY" "$SLOW" > "$DIR/flatpak-curl.out" 2>&1 &
    pid=$!
    sleep 1.2
    describe_pid flatpak-curl "$(pgrep -n -x curl)"
    observe flatpak-curl "$pid"
  elif grep -q python3 <<< "$probe"; then
    cp "$DIR/client.py" /tmp/nsclient.py && chmod a+r /tmp/nsclient.py
    as_user flatpak run --share=network --filesystem=/tmp --command=python3 "$runtime" /tmp/nsclient.py "$PROXY" "$SLOW" > "$DIR/flatpak-python.out" 2>&1 &
    pid=$!
    sleep 1.2
    describe_pid flatpak-python "$(pgrep -n python3)"
    observe flatpak-python3 "$pid"
  else
    note "flatpak: the runtime ran but has neither curl nor python3: $probe"
  fi
  # A real Flatpak app keeps its own programs under /app: a tiny one whose
  # program is the runtime's curl, installed from a local repository.
  build_flatpak_app() {
    local work="$DIR/flatpak-app" location
    rm -rf "$work"
    mkdir -p "$work"
    location=$(flatpak info --system --show-location "$runtime") || return 1
    flatpak build-init "$work/app" com.example.NsCurl org.freedesktop.Platform org.freedesktop.Platform "$flatpak_ok" || return 1
    mkdir -p "$work/app/files/bin"
    cp "$location/files/bin/curl" "$work/app/files/bin/curl" || return 1
    flatpak build-finish "$work/app" --command=curl --share=network || return 1
    flatpak build-export "$work/repo" "$work/app" || return 1
    flatpak remote-add --system --no-gpg-verify --if-not-exists nslocal "$work/repo" || return 1
    flatpak install --system -y --noninteractive nslocal com.example.NsCurl
  }
  if build_flatpak_app > "$DIR/flatpak-app.log" 2>&1; then
    as_user flatpak run com.example.NsCurl -s -x "$PROXY" "$SLOW" > "$DIR/flatpak-app.out" 2>&1 &
    pid=$!
    sleep 1.2
    describe_pid flatpak-app "$(pgrep -n -x curl)"
    observe flatpak-app-com.example.NsCurl "$pid"
  else
    note "flatpak app: couldn't build one here: $(tail -3 "$DIR/flatpak-app.log" | tr '\n' ' ')"
  fi
  rm -rf "$DIR/flatpak-app"
else
  note "flatpak: not possible here: $(tail -3 "$DIR/flatpak-install.log" | tr '\n' ' ')"
fi

# AppImage: a tiny one wrapping this system's curl, built with the pinned appimagetool.
build_appimage() {
  local work="$DIR/appimage"
  timeout 120 apt-get install -y -q fuse3 || true
  /usr/bin/curl -fsSL --retry 3 -o "$work/appimagetool" "$APPIMAGETOOL_URL/appimagetool-$APPIMAGE_ARCH.AppImage" &&
    /usr/bin/curl -fsSL --retry 3 -o "$work/runtime" "$RUNTIME_URL/runtime-$APPIMAGE_ARCH" || return 1
  printf '%s  %s\n' "$APPIMAGETOOL_SHA" "$work/appimagetool" "$RUNTIME_SHA" "$work/runtime" | sha256sum -c - || return 1
  chmod +x "$work/appimagetool"
  cp /usr/bin/curl "$work/AppDir/usr/bin/curl"
  printf '%s\n' '#!/bin/sh' 'exec "$APPDIR/usr/bin/curl" "$@"' > "$work/AppDir/AppRun"
  chmod +x "$work/AppDir/AppRun"
  printf '%s\n' '[Desktop Entry]' 'Type=Application' 'Name=NsCurl' 'Exec=curl' 'Icon=nscurl' 'Categories=Network;' > "$work/AppDir/nscurl.desktop"
  printf '%s\n' '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" fill="#3a6"/></svg>' > "$work/AppDir/nscurl.svg"
  ARCH=$APPIMAGE_ARCH APPIMAGE_EXTRACT_AND_RUN=1 "$work/appimagetool" --no-appstream --runtime-file "$work/runtime" "$work/AppDir" "$work/NsCurl.AppImage" || return 1
  chmod a+rx "$work" "$work/NsCurl.AppImage"
}
rm -rf "$DIR/appimage"
mkdir -p "$DIR/appimage/AppDir/usr/bin"
if build_appimage > "$DIR/appimage-build.log" 2>&1; then
  appimage="$DIR/appimage/NsCurl.AppImage"
  as_user "$appimage" -s -x "$PROXY" "$SLOW" > "$DIR/appimage.out" 2>&1 &
  pid=$!
  sleep 1.2
  describe_pid appimage "$(pgrep -n -x curl)"
  observe appimage-fuse-mount "$pid"
  as_user env APPIMAGE_EXTRACT_AND_RUN=1 "$appimage" -s -x "$PROXY" "$SLOW" > "$DIR/appimage-extracted.out" 2>&1 &
  observe appimage-extract-and-run $!
else
  note "AppImage: not possible here: $(tail -3 "$DIR/appimage-build.log" 2>/dev/null | tr '\n' ' ')"
fi
# Keep the uploaded results to text.
rm -rf "$DIR/appimage/AppDir" "$DIR/appimage/appimagetool" "$DIR/appimage/runtime" "$DIR/appimage/NsCurl.AppImage"

block "engine log" "$(tail -20 "$DIR/engine.log")"
engine_stop
kill "$SERVER_PID" 2>/dev/null
CHECK=total
note "$(grep -c '^PASS' "$RESULTS") PASS, $(grep -c '^FAIL' "$RESULTS") FAIL"
finish
exit 0
