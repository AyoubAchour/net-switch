# Shared helpers for the Linux spike, sourced by run-checks.sh and identity.sh.
# Everything here runs as root on a CI runner.
#
# Topology (network namespaces):
#   dut   sing-box and the test apps; vethA -> ispA (main line A), vethB -> ispB (line B)
#   ispA  192.168.10.1 on its LAN, NATs to 192.0.2.1 on the fake internet
#   ispB  192.168.20.1 on its LAN, NATs to 192.0.2.2 on the fake internet
#   inet  bridge br0 with the servers on 192.0.2.10-19 and 192.0.2.30
# The servers answer with the source address they saw, so .1 means line A and
# .2 means line B.

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=${OUT:-/tmp/spike-out}
SB=${SB:-/opt/sing-box/sing-box}
NODE=${NODE:-$(command -v node)}
APP_UID=${APP_UID:-1001}
APP_GID=${APP_GID:-$APP_UID}
APP_HOME=$(getent passwd "$APP_UID" | cut -d: -f6)
APP_HOME=${APP_HOME:-/tmp}
SUMMARY="$OUT/summary.md"
RESULTS="$OUT/results.txt"
CLK_TCK=$(getconf CLK_TCK)
CHECK=setup
SB_PID=
LINKS=0
mkdir -p "$OUT"
chmod 755 "$OUT"
ulimit -n 65536 2>/dev/null || true

say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
summary() { printf '%s\n' "$*" >> "$SUMMARY"; }
pass() { say "PASS [$CHECK] $*"; summary "- PASS: $*"; }
fail() { say "FAIL [$CHECK] $*"; summary "- **FAIL**: $*"; }
info() { say "INFO [$CHECK] $*"; }
note() { say "INFO [$CHECK] $*"; summary "- $*"; }
begin() {
  CHECK=$1
  say ""
  say "===== $1: $2 ====="
  summary ""
  summary "### $1: $2"
}
# Indented raw output in the log, and as a code block in the summary.
block() {
  local title=$1 text=$2
  say "    --- $title"
  printf '%s\n' "$text" | sed 's/^/    /' | tee -a "$RESULTS"
  summary ""
  summary "<details><summary>$title</summary>"
  summary ""
  summary '```'
  printf '%s\n' "$text" >> "$SUMMARY"
  summary '```'
  summary "</details>"
  summary ""
}

now_ms() {
  local t=${EPOCHREALTIME//[.,]/}
  echo $((t / 1000))
}

wait_for() {
  local what=$1 seconds=$2
  shift 2
  local deadline=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      info "timed out after ${seconds}s waiting for $what"
      return 1
    fi
    sleep 0.2
  done
}

line_of() {
  case "$1" in
    192.0.2.1) echo A ;;
    192.0.2.2) echo B ;;
    *) echo "?" ;;
  esac
}

in_dut() { ip netns exec dut "$@"; }
# A test app run as the runner's own user, as a desktop app would be.
as_app() { ip netns exec dut setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups env HOME="$APP_HOME" "$@"; }

NAMESPACES="dut ispA ispB inet ctr"
topo_down() {
  local ns pid
  for ns in $NAMESPACES; do
    if [ -e "/run/netns/$ns" ]; then
      for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -9 "$pid" 2>/dev/null; done
      ip netns del "$ns" 2>/dev/null
    fi
  done
  SB_PID=
  sleep 0.3
}

# link NS1 IF1 NS2 IF2: a veth pair between two namespaces.
link() {
  LINKS=$((LINKS + 1))
  local a="spk${LINKS}a" b="spk${LINKS}b"
  ip link add "$a" type veth peer name "$b" &&
    ip link set "$a" netns "$1" && ip link set "$b" netns "$3" &&
    ip -n "$1" link set "$a" name "$2" && ip -n "$3" link set "$b" name "$4" &&
    ip -n "$1" link set "$2" up && ip -n "$3" link set "$4" up
}

topo_up() {
  topo_down
  local ns
  for ns in dut ispA ispB inet; do
    ip netns add "$ns" || return 1
    ip -n "$ns" link set lo up
  done
  ip -n inet link add br0 type bridge && ip -n inet link set br0 up || return 1
  local host
  for host in 10 11 12 13 14 15 16 17 18 19 30; do ip -n inet addr add "192.0.2.$host/24" dev br0; done
  local isp n
  for isp in A B; do
    if [ "$isp" = A ]; then n=1; else n=2; fi
    link "isp$isp" wan inet "up$isp" || return 1
    ip -n inet link set "up$isp" master br0
    ip -n "isp$isp" addr add "192.0.2.$n/24" dev wan
    link dut "veth$isp" "isp$isp" lan || return 1
    ip -n "isp$isp" addr add "192.168.${n}0.1/24" dev lan
    ip -n dut addr add "192.168.${n}0.2/24" dev "veth$isp"
    ip netns exec "isp$isp" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "isp$isp" nft add table ip nat
    ip netns exec "isp$isp" nft add chain ip nat post '{ type nat hook postrouting priority 100 ; }'
    ip netns exec "isp$isp" nft add rule ip nat post oifname wan masquerade
  done
  # Like NetworkManager with two connections: both have a default route, the
  # main line's with the lower metric.
  ip -n dut route add default via 192.168.10.1 dev vethA metric 100
  ip -n dut route add default via 192.168.20.1 dev vethB metric 200
}

servers_up() {
  rm -f "$OUT/server.log"
  ip netns exec inet "$NODE" "$HERE/server.mjs" > "$OUT/server.log" 2>&1 &
  wait_for "the fake internet's servers" 15 grep -q ready "$OUT/server.log" || return 1
  if [ "${1:-}" = iperf ]; then
    ip netns exec inet iperf3 -s -D -B 192.0.2.10 || return 1
    sleep 0.5
  fi
}

apps_setup() {
  local app
  for app in alpha bravo; do
    mkdir -p "/opt/nsapps/$app"
    cp "$(command -v curl)" "/opt/nsapps/$app/curl"
    cp "$(readlink -f "$NODE")" "/opt/nsapps/$app/node"
  done
  chmod -R a+rX /opt/nsapps
}

# gen DIR [config.mjs options]: a config and rule files in DIR.
gen() {
  local dir=$1
  shift
  mkdir -p "$dir" && chmod 777 "$dir"
  "$NODE" "$HERE/config.mjs" --out "$dir" "$@"
}

# The engine's API: api NS PATH [METHOD]. NS "root" is the runner's own namespace.
API_PORT=9090
api() {
  local ns=$1 route=$2 method=${3:-GET}
  if [ "$ns" = root ]; then
    curl -s --max-time 5 -H "Authorization: Bearer spike" -X "$method" "http://127.0.0.1:$API_PORT$route"
  else
    ip netns exec "$ns" curl -s --max-time 5 -H "Authorization: Bearer spike" -X "$method" "http://127.0.0.1:$API_PORT$route"
  fi
}
api_ok() { api "$1" /version | grep -q version; }

# engine_start DIR [NS]: runs sing-box with DIR/config.json and waits until
# its API answers and (for TUN configs) its interface exists.
engine_start() {
  local dir=$1 ns=${2:-dut}
  if [ "$ns" = root ]; then
    "$SB" run -c "$dir/config.json" --disable-color > "$dir/engine.log" 2>&1 &
  else
    ip netns exec "$ns" "$SB" run -c "$dir/config.json" --disable-color > "$dir/engine.log" 2>&1 &
  fi
  SB_PID=$!
  if ! wait_for "the engine's API" 20 api_ok "$ns"; then
    fail "the engine did not start"
    block "engine log" "$(tail -20 "$dir/engine.log")"
    return 1
  fi
  if grep -q '"type": "tun"' "$dir/config.json"; then
    wait_for "the TUN interface" 10 ip -n "$ns" link show NetSwitch || return 1
  fi
  sleep 0.5
}

engine_stop() {
  [ -n "$SB_PID" ] || return 0
  kill -TERM "$SB_PID" 2>/dev/null
  local i
  for i in $(seq 50); do
    kill -0 "$SB_PID" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$SB_PID" 2>/dev/null
  wait "$SB_PID" 2>/dev/null
  SB_PID=
}

# The engine's CPU time so far (user + system), in ms.
cpu_ms() {
  local stat
  stat=$(cat "/proc/$SB_PID/stat" 2>/dev/null) || {
    echo 0
    return
  }
  stat=${stat##*) }
  # shellcheck disable=SC2086
  set -- $stat
  echo $(((${12} + ${13}) * 1000 / CLK_TCK))
}

# expect_seen LABEL WANT COMMAND...: the command prints the address the server saw.
expect_seen() {
  local label=$1 want=$2
  shift 2
  local got
  got=$("$@" 2>&1 | tail -1)
  if [ "$got" = "$want" ]; then
    pass "$label -> $got (line $(line_of "$got"))"
  else
    fail "$label -> '${got:-no answer}', expected $want (line $(line_of "$want"))"
  fi
}

# Everything the engine might leave behind in dut.
snapshot() {
  {
    echo "## ip rule"
    ip -n dut rule show
    echo "## ip -6 rule"
    ip -n dut -6 rule show
    echo "## ip route show table all"
    ip -n dut route show table all
    echo "## ip -6 route show table all"
    ip -n dut -6 route show table all
    echo "## nft list ruleset"
    ip netns exec dut nft list ruleset
    echo "## links"
    ip -n dut -br link | awk '{print $1}'
  } > "$1" 2>&1
}

# Packets dropped by the reverse-path filter in dut so far.
rpf_drops() {
  in_dut awk '/^TcpExt:/ { if (!header) { for (i = 1; i <= NF; i++) name[i] = $i; header = 1 } else { for (i = 1; i <= NF; i++) if (name[i] == "IPReversePathFilter") print $i } }' /proc/net/netstat
}

finish() {
  topo_down
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$SUMMARY" ]; then cat "$SUMMARY" >> "$GITHUB_STEP_SUMMARY"; fi
  chmod -R a+rX "$OUT"
}
