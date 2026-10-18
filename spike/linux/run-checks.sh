#!/usr/bin/env bash
# Linux feasibility checks 1-11 and 13 for Net Switch's routing engine
# (sing-box TUN), in network namespaces on a CI runner, so the runner's own
# connection is never routed. Needs root. CHECKS="check2 check6" runs only those.
set -uo pipefail
# shellcheck source=spike/linux/lib.sh
source "$(dirname "$0")/lib.sh"

URL=http://192.0.2.10:8080/
WHOAMI=192.0.2.10:7003
CLIENT="$HERE/client.mjs"
ANALYZE="$HERE/analyze.mjs"

check1() {
  begin check1 "Runner facts"
  local name
  name=$(. /etc/os-release && echo "$PRETTY_NAME")
  note "OS: $name, kernel $(uname -r), $(uname -m), $(nproc) CPUs"
  local fs
  fs=$(stat -fc %T /sys/fs/cgroup)
  note "cgroup v2: $([ "$fs" = cgroup2fs ] && echo yes || echo no) (/sys/fs/cgroup is $fs)"
  note "BTF (/sys/kernel/btf/vmlinux): $([ -e /sys/kernel/btf/vmlinux ] && echo yes || echo no)"
  note "nft: $(nft --version 2>&1 | head -1)"
  note "systemd: $(systemctl --version | head -1)"
  note "NetworkManager: $(systemctl is-active NetworkManager 2>&1 | head -1), nmcli $(command -v nmcli || echo missing); systemd-networkd: $(systemctl is-active systemd-networkd 2>&1 | head -1); systemd-resolved: $(systemctl is-active systemd-resolved 2>&1 | head -1)"
  local dev
  dev=$(ip route show default | awk '{ print $5; exit }')
  note "rp_filter in the root namespace: all=$(sysctl -n net.ipv4.conf.all.rp_filter) default=$(sysctl -n net.ipv4.conf.default.rp_filter) $dev=$(sysctl -n "net.ipv4.conf.$dev.rp_filter")"
  ip netns add probe
  note "rp_filter in a new namespace: all=$(ip netns exec probe sysctl -n net.ipv4.conf.all.rp_filter) default=$(ip netns exec probe sysctl -n net.ipv4.conf.default.rp_filter); net.core.devconf_inherit_init_net=$(sysctl -n net.core.devconf_inherit_init_net 2>&1)"
  ip netns del probe
  note "ephemeral ports: $(sysctl -n net.ipv4.ip_local_port_range | tr -s '\t ' ' ')"
  note "AppArmor restricts unprivileged user namespaces: $(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>&1)"
  note "firewalls: ufw $(ufw status 2>&1 | head -1); firewalld $(systemctl is-active firewalld 2>&1 | head -1); docker0 $(ip -br link show docker0 2>/dev/null | awk '{ print $2 }')"
  note "$("$SB" version | head -1); Node $("$NODE" --version); $(ip -V); $(iperf3 --version | head -1); $(curl --version | head -1 | cut -d' ' -f1-2)"
  note "sudo: $(sudo --version 2>&1 | head -1); coreutils: $(ls --version 2>&1 | head -1)"
}

# udp_check LABEL WANT COMMAND...: the command is client.mjs udp.
udp_check() {
  local label=$1 want=$2
  shift 2
  local out seen sent received
  out=$("$@" 2>&1 | tail -1)
  seen=$(jq -r '.seen | keys | join(",")' <<< "$out" 2>/dev/null)
  sent=$(jq -r '.sent' <<< "$out" 2>/dev/null)
  received=$(jq -r '.received' <<< "$out" 2>/dev/null)
  if [ "$seen" = "$want" ] && [ "$received" = "$sent" ]; then
    pass "$label -> $received/$sent answered, all via $want (line $(line_of "$want"))"
  else
    fail "$label -> $out (expected all via $want)"
  fi
}

check2() {
  begin check2 "Per-app routing through the TUN (gvisor stack)"
  topo_up && servers_up || {
    fail "topology did not come up"
    return
  }
  expect_seen "no engine: plain curl (main route)" 192.0.2.1 in_dut curl -s --max-time 5 "$URL"
  expect_seen "no engine: curl bound to vethB" 192.0.2.2 in_dut curl -s --max-time 5 --interface vethB "$URL"
  local dir="$OUT/check2"
  gen "$dir" && engine_start "$dir" || return
  expect_seen "alpha curl (unplaced, runner user)" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
  expect_seen "bravo curl (placed on B, runner user)" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
  expect_seen "bravo curl run as root" 192.0.2.2 in_dut /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
  expect_seen "host /usr/bin/curl (unplaced)" 192.0.2.1 as_app curl -s --max-time 5 "$URL"
  udp_check "alpha UDP echo (unplaced), 2 sockets x 20 datagrams" 192.0.2.1 \
    as_app /opt/nsapps/alpha/node "$CLIENT" udp --to 192.0.2.10:7001 --count 20 --sockets 2
  udp_check "bravo UDP echo (placed on B), 2 sockets x 20 datagrams" 192.0.2.2 \
    as_app /opt/nsapps/bravo/node "$CLIENT" udp --to 192.0.2.10:7001 --count 20 --sockets 2
  note "QUIC: not tested. This runner's curl $(curl --version | grep -q HTTP3 && echo has || echo lacks) HTTP/3 and the fake internet has no QUIC server; the UDP echo above covers datagram routing."
  block "ip rule while the engine runs" "$(ip -n dut rule show)"
  block "ip -6 rule while the engine runs" "$(ip -n dut -6 rule show)"
  block "route table 3110 while the engine runs" "$( (ip -n dut route show table 3110; ip -n dut -6 route show table 3110) | compact)"
  block "engine log" "$(tail -15 "$dir/engine.log")"
  engine_stop
  topo_down
}

check3() {
  begin check3 "Clash API process metadata"
  topo_up && servers_up || {
    fail "topology did not come up"
    return
  }
  local dir="$OUT/check3"
  gen "$dir" && engine_start "$dir" || return
  local pids=()
  as_app /opt/nsapps/bravo/curl -s --max-time 10 "${URL}slow?ms=4000" > /dev/null &
  pids+=($!)
  as_app /opt/nsapps/alpha/curl -s --max-time 10 "${URL}slow?ms=4000" > /dev/null &
  pids+=($!)
  in_dut /opt/nsapps/alpha/curl -s --max-time 10 "${URL}slow?ms=4000" > /dev/null &
  pids+=($!)
  as_app /opt/nsapps/bravo/node "$CLIENT" udp --to 192.0.2.10:7001 --count 3 --hold 4000 > /dev/null &
  pids+=($!)
  sleep 2
  api dut /connections > "$dir/connections.json"
  block "connections as the Clash API reports them" "$("$NODE" "$ANALYZE" conns < "$dir/connections.json")"
  local paths
  paths=$(jq -r '.connections[].metadata.processPath' "$dir/connections.json" | sort -u)
  note "processPath values: $(sed 's/.*/`&`/' <<< "$paths" | paste -sd ' ' -)"
  if grep -qx '/opt/nsapps/bravo/curl (.*)' <<< "$paths"; then
    pass "processPath is the binary plus a user suffix: $(grep -m1 'bravo/curl' <<< "$paths")"
  else
    fail "bravo's processPath is not '<path> (<user>)': $(grep -m1 'bravo/curl' <<< "$paths")"
  fi
  wait "${pids[@]}"
  engine_stop
  topo_down
}

check4() {
  begin check4 "Engine stacks: throughput, CPU and errors"
  summary ""
  summary "| stack | iperf3, 1 stream | iperf3, 8 streams | sing-box CPU, 1 / 8 streams | CPU per GB, 1 / 8 | 500 connections, 20 at once | firewall-like input drop (TCP alpha, TCP bravo, UDP bravo) |"
  summary "|---|---|---|---|---|---|---|"
  local stack
  for stack in none gvisor system mixed; do
    topo_up && servers_up iperf || {
      fail "$stack: topology did not come up"
      continue
    }
    local dir="$OUT/check4-$stack"
    mkdir -p "$dir" && chmod 777 "$dir"
    if [ "$stack" != none ]; then
      gen "$dir" --stack "$stack" && engine_start "$dir" || {
        fail "$stack: engine did not start"
        continue
      }
    fi
    local c0 c1 c2 one eight burst
    c0=$(cpu_ms)
    in_dut timeout 40 iperf3 -c 192.0.2.10 -t 8 -O 1 -J > "$dir/iperf1.json" 2>&1
    c1=$(cpu_ms)
    in_dut timeout 40 iperf3 -c 192.0.2.10 -t 8 -O 1 -P 8 -J > "$dir/iperf8.json" 2>&1
    c2=$(cpu_ms)
    one=$("$NODE" "$ANALYZE" iperf --file "$dir/iperf1.json")
    eight=$("$NODE" "$ANALYZE" iperf --file "$dir/iperf8.json")
    burst=$(as_app /opt/nsapps/alpha/node "$CLIENT" whoami --to "$WHOAMI" --count 500 --concurrency 20 2>&1 | tail -1)
    local burst_text
    burst_text=$(jq -r '"\(.ok) ok, errors \(.errors | tostring), p50 \(.p50) ms, p95 \(.p95) ms"' <<< "$burst" 2>/dev/null || echo "$burst")
    # Roughly what firewalld does: new inbound connections are refused unless allowed.
    in_dut nft add table inet spikefw
    in_dut nft add chain inet spikefw input '{ type filter hook input priority 0 ; policy drop ; }'
    in_dut nft add rule inet spikefw input ct state established,related accept
    in_dut nft add rule inet spikefw input iif lo accept
    local fa fb fu
    fa=$(as_app /opt/nsapps/alpha/curl -s --max-time 4 "$URL")
    fb=$(as_app /opt/nsapps/bravo/curl -s --max-time 4 "$URL")
    fu=$(as_app /opt/nsapps/bravo/node "$CLIENT" udp --to 192.0.2.10:7001 --count 5 2>&1 | tail -1 | jq -r '"\(.received)/\(.sent) \(.seen | keys | join(","))"' 2>/dev/null)
    in_dut nft delete table inet spikefw
    local cpu1=$((c1 - c0)) cpu8=$((c2 - c1)) gb1 gb8 per1 per8
    gb1=$(awk '{ print $3 }' <<< "$one")
    gb8=$(awk '{ print $3 }' <<< "$eight")
    per1=$(awk -v c="$cpu1" -v g="$gb1" 'BEGIN { if (g > 0) printf "%.0f ms", c / g; else print "n/a" }')
    per8=$(awk -v c="$cpu8" -v g="$gb8" 'BEGIN { if (g > 0) printf "%.0f ms", c / g; else print "n/a" }')
    if [ "$stack" = none ]; then
      cpu1=n/a cpu8=n/a per1=n/a per8=n/a
    fi
    info "$stack: 1 stream $one; 8 streams $eight; sing-box CPU $cpu1 / $cpu8 ms; burst $burst; firewall: alpha '${fa}' bravo '${fb}' udp '${fu}'"
    summary "| $stack | $one | $eight | $cpu1 / $cpu8 ms | $per1 / $per8 | $burst_text | ${fa:-no answer}, ${fb:-no answer}, ${fu:-no answer} |"
    engine_stop
    topo_down
  done
  summary ""
}

uid_fds() {
  local total=0 p n
  for p in /proc/[0-9]*; do
    [ "$(stat -c %u "$p" 2>/dev/null)" = "$1" ] || continue
    n=$(ls "$p/fd" 2>/dev/null | wc -l)
    total=$((total + n))
  done
  echo "$total"
}

check5() {
  begin check5 "Process lookup cost: 2,000 short connections, 10 at a time, then 300 one at a time"
  summary ""
  summary "| variant | wall time | sing-box CPU | CPU per connection | p50 / p95, 10 at once | handshakes over 1 s | errors | p50 one at a time | open fds of the app's user |"
  summary "|---|---|---|---|---|---|---|---|---|"
  local variant
  for variant in ${CHECK5_VARIANTS:-off on on+5000-files-same-user on+5000-files-root system-off system-on system-on+5000-files-same-user on-info-log}; do
    topo_up && servers_up || {
      fail "$variant: topology did not come up"
      continue
    }
    local dir="$OUT/check5-${variant//+/-}" opts=()
    case "$variant" in *off*) opts+=(--no-rules) ;; esac
    case "$variant" in system*) opts+=(--stack system) ;; esac
    case "$variant" in *info-log*) opts+=(--log-level info) ;; esac
    gen "$dir" "${opts[@]}" && engine_start "$dir" || continue
    local holder=
    case "$variant" in
      *same-user)
        as_app "$NODE" "$CLIENT" hold-files --count 5000 > "$dir/holder.log" 2>&1 &
        holder=$!
        ;;
      *root)
        in_dut "$NODE" "$CLIENT" hold-files --count 5000 > "$dir/holder.log" 2>&1 &
        holder=$!
        ;;
    esac
    if [ -n "$holder" ]; then
      wait_for "the file holder" 20 grep -q holding "$dir/holder.log" || fail "$variant: holder: $(cat "$dir/holder.log")"
    fi
    local fds c0 c1 result serial
    fds=$(uid_fds "$APP_UID")
    c0=$(cpu_ms)
    # A long timeout shows whether stuck connections ever finish (SYN retries at 1, 3, 7, 15, 31 s).
    result=$(as_app /opt/nsapps/alpha/node "$CLIENT" whoami --to "$WHOAMI" --count 2000 --concurrency 10 --timeout 35000 2>&1 | tail -1)
    c1=$(cpu_ms)
    serial=$(as_app /opt/nsapps/alpha/node "$CLIENT" whoami --to "$WHOAMI" --count 300 --concurrency 1 --timeout 35000 2>&1 | tail -1)
    local cpu=$((c1 - c0))
    info "$variant: $result; one at a time: $serial; sing-box CPU $cpu ms; fds of uid $APP_UID: $fds; engine log lines: $(wc -l < "$dir/engine.log")"
    summary "$(jq -r --arg cpu "$cpu" --arg fds "$fds" --arg v "$variant" --arg serial "$(jq -r .p50 <<< "$serial" 2>/dev/null)" \
      '"| \($v) | \(.wallMs) ms | \($cpu) ms | \(($cpu | tonumber) * 1000 / 2000 | floor) µs | \(.p50) / \(.p95) ms | \(.over1s) | \(.errors | tostring) | \($serial) ms | \($fds) |"' <<< "$result" 2>/dev/null || echo "| $variant | $result |")"
    if grep -q -i -E 'error|warn' "$dir/engine.log"; then
      info "$variant: engine log: $(grep -i -E 'error|warn' "$dir/engine.log" | cut -c1-200 | sort | uniq -c | sort -rn | head -3 | tr '\n' ' ')"
    fi
    case "$variant" in
      *info-log*)
        # The kinds of engine messages, numbers masked, rarest last.
        block "$variant: engine message kinds" "$(sed -E 's/^.*(INFO|WARN|ERROR|DEBUG) \[[^]]*\] //; s/[0-9]+/N/g' "$dir/engine.log" | sort | uniq -c | sort -rn | head -25)"
        ;;
    esac
    if [ -n "$holder" ]; then
      kill "$holder" 2>/dev/null
      wait "$holder" 2>/dev/null
    fi
    engine_stop
    topo_down
  done
  summary ""
}

run_combine() {
  local dir=$1 share=$2 label=$3
  shift 3
  local file="$dir/combine-$((++COMBINE_RUN)).json" result first rest
  as_app /opt/nsapps/alpha/node "$CLIENT" whoami "$@" --out "$file" > /dev/null
  result=$("$NODE" "$ANALYZE" combine --file "$file" --share-b "$share" 2>&1)
  first=${result%%$'\n'*}
  rest=${result#*$'\n'}
  case "$first" in
    PASS*) pass "$label: ${first#PASS }" ;;
    *) fail "$label: ${first#FAIL }" ;;
  esac
  info "$label: $rest"
}

check6() {
  begin check6 "Combine split on Linux: A 2/3, B 1/3 by source port"
  topo_up && servers_up || {
    fail "topology did not come up"
    return
  }
  local dir="$OUT/check6" share=0.3333333333333333
  gen "$dir" --share-b "$share" && engine_start "$dir" || return
  local dests="" host
  for host in 10 11 12 13 14 15 16 17 18 19; do dests+="${dests:+,}192.0.2.$host:7003"; done
  COMBINE_RUN=0
  run_combine "$dir" "$share" "300 to one destination, one at a time" --to "$WHOAMI" --count 300 --concurrency 1
  run_combine "$dir" "$share" "300 to one destination, 16 at once" --to "$WHOAMI" --count 300 --concurrency 16
  run_combine "$dir" "$share" "300 over 10 destinations, one at a time" --to "$dests" --count 300 --concurrency 1
  run_combine "$dir" "$share" "300 over 10 destinations, 16 at once" --to "$dests" --count 300 --concurrency 16
  engine_stop
  topo_down
}

check7() {
  begin check7 "Connections opened before the engine starts"
  local spec
  for spec in gvisor:ranges system:ranges gvisor:none gvisor:own-rules; do
    local stack=${spec%%:*} variant=${spec#*:}
    topo_up && servers_up || {
      fail "$spec: topology did not come up"
      continue
    }
    local dir="$OUT/check7-$stack-$variant"
    # shellcheck disable=SC2046
    gen "$dir" --stack "$stack" $(variant_flags "$variant") || continue
    local pa pb
    as_app /opt/nsapps/alpha/node "$CLIENT" stream --to 192.0.2.10:7002 --seconds 28 --interval 250 --log "$dir/alpha.log" &
    pa=$!
    as_app /opt/nsapps/bravo/node "$CLIENT" stream --to 192.0.2.10:7002 --seconds 28 --interval 250 --log "$dir/bravo.log" &
    pb=$!
    sleep 4
    local t_start t_ready t_stop
    t_start=$(now_ms)
    variant_setup "$variant"
    engine_start "$dir" || {
      kill "$pa" "$pb" 2>/dev/null
      continue
    }
    t_ready=$(now_ms)
    info "$spec: an established socket's route now: $(in_dut ip route get 192.0.2.10 from 192.168.10.2 2>&1 | head -1); a new socket's: $(in_dut ip route get 192.0.2.10 2>&1 | head -1)"
    expect_seen "$spec: a new bravo connection while the engine runs" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
    expect_seen "$spec: a new alpha connection while the engine runs" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
    sleep 10
    t_stop=$(now_ms)
    engine_stop
    wait "$pa" "$pb"
    local app result
    for app in alpha bravo; do
      result=$("$NODE" "$ANALYZE" stream --log "$dir/$app.log" --start "$t_start" --ready "$t_ready" --stop "$t_stop" 2>&1)
      note "$spec, $app ($([ "$app" = alpha ] && echo unplaced || echo placed on B)), engine ran $(((t_stop - t_ready) / 1000)) s: $result"
    done
    topo_down
  done
}

check8() {
  begin check8 "Cleanup after a clean stop and after kill -9"
  local mode
  for mode in off on; do
    topo_up && servers_up || {
      fail "topology did not come up"
      continue
    }
    local dir="$OUT/check8-auto-redirect-$mode" label="auto_redirect $mode" left burst
    if [ "$mode" = on ]; then gen "$dir" --auto-redirect; else gen "$dir"; fi || continue
    snapshot "$dir/before.txt"
    # First a clean start and stop.
    engine_start "$dir" && engine_stop
    snapshot "$dir/after-clean-stop.txt"
    left=$(diff "$dir/before.txt" "$dir/after-clean-stop.txt" | grep '^[<>]')
    if [ -z "$left" ]; then
      pass "$label: a clean stop leaves nothing behind"
    else
      fail "$label: a clean stop leaves $(grep -c . <<< "$left") lines behind"
      block "$label: left behind after a clean stop (> still there, < missing)" "$(compact <<< "$left")"
    fi
    snapshot "$dir/before.txt"
    engine_start "$dir" || continue
    expect_seen "$label, running: alpha" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
    expect_seen "$label, running: bravo" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
    snapshot "$dir/running.txt"
    block "$label: what the engine adds while running (> added, < removed)" "$(diff "$dir/before.txt" "$dir/running.txt" | grep '^[<>]' | compact)"
    kill -9 "$SB_PID"
    wait "$SB_PID" 2>/dev/null
    SB_PID=
    sleep 2
    snapshot "$dir/after-kill.txt"
    left=$(diff "$dir/before.txt" "$dir/after-kill.txt" | grep '^[<>]')
    if [ -z "$left" ]; then
      pass "$label: nothing left behind after kill -9"
    else
      fail "$label: kill -9 left $(grep -c . <<< "$left") lines behind"
      block "$label: left behind after kill -9 (> still there, < missing)" "$(compact <<< "$left")"
    fi
    expect_seen "$label, after kill -9: alpha curl" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
    expect_seen "$label, after kill -9: bravo curl" 192.0.2.1 as_app /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
    expect_seen "$label, after kill -9: curl bound to vethB" 192.0.2.2 in_dut curl -s --max-time 5 --interface vethB "$URL"
    burst=$(as_app /opt/nsapps/alpha/node "$CLIENT" whoami --to "$WHOAMI" --count 50 --concurrency 5 --timeout 4000 2>&1 | tail -1)
    if [ "$(jq -r .ok <<< "$burst" 2>/dev/null)" = 50 ]; then
      pass "$label, after kill -9: 50/50 new TCP connections work"
    else
      fail "$label, after kill -9: new TCP connections -> $burst"
    fi
    udp_check "$label, after kill -9: UDP" 192.0.2.1 as_app /opt/nsapps/alpha/node "$CLIENT" udp --to 192.0.2.10:7001 --count 5
    # Does the next start clean up what the killed one left?
    engine_start "$dir" && engine_stop
    snapshot "$dir/after-restart.txt"
    left=$(diff "$dir/before.txt" "$dir/after-restart.txt" | grep '^[<>]')
    if [ -z "$left" ]; then
      pass "$label: the next start and a clean stop put everything back"
    else
      fail "$label: still left after the next start and a clean stop"
      block "$label: left after restart + clean stop" "$(compact <<< "$left")"
    fi
    expect_seen "$label, after restart + clean stop: alpha curl" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
    topo_down
  done
}

# rpf_try LABEL WANT COMMAND...: like expect_seen, with the rp_filter drop count.
rpf_try() {
  local label=$1 want=$2
  shift 2
  local before after got
  before=$(rpf_drops)
  got=$("$@" 2>&1 | tail -1)
  after=$(rpf_drops)
  if [ "$got" = "$want" ]; then
    pass "$label -> $got (rp_filter drops +$((after - before)))"
  else
    fail "$label -> '${got:-no answer}', expected $want (rp_filter drops +$((after - before)))"
  fi
}

check9() {
  begin check9 "Strict reverse-path filtering (rp_filter=1) on dut"
  local variant
  for variant in ranges none own-rules; do
    topo_up && servers_up || {
      fail "$variant: topology did not come up"
      continue
    }
    local key
    for key in all default lo vethA vethB; do in_dut sysctl -qw "net.ipv4.conf.$key.rp_filter=1"; done
    if [ "$variant" = ranges ]; then
      rpf_try "no engine: curl bound to vethB" 192.0.2.2 in_dut curl -s --max-time 4 --interface vethB "$URL"
      rpf_try "no engine: plain curl (main line)" 192.0.2.1 in_dut curl -s --max-time 4 "$URL"
    fi
    local dir="$OUT/check9-$variant"
    # shellcheck disable=SC2046
    gen "$dir" $(variant_flags "$variant") || continue
    variant_setup "$variant"
    engine_start "$dir" || continue
    [ "$variant" = ranges ] && info "NetSwitch interface rp_filter=$(in_dut sysctl -n net.ipv4.conf.NetSwitch.rp_filter)"
    rpf_try "$variant: bravo (placed on B)" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 4 "$URL"
    rpf_try "$variant: alpha (unplaced)" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 4 "$URL"
    # The fix: per line, a table with its default route and a rule for its own
    # address, so the reverse lookup for a reply finds the line it came in on.
    in_dut ip route add default via 192.168.10.1 dev vethA table 3200
    in_dut ip route add default via 192.168.20.1 dev vethB table 3201
    in_dut ip rule add from 192.168.10.2 lookup 3200 pref 31000
    in_dut ip rule add from 192.168.20.2 lookup 3201 pref 31000
    rpf_try "$variant + a source rule per line: bravo" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 4 "$URL"
    rpf_try "$variant + a source rule per line: alpha" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 4 "$URL"
    rpf_try "$variant + a source rule per line: bravo UDP" 192.0.2.2 sh -c "ip netns exec dut setpriv --reuid=$APP_UID --regid=$APP_GID --clear-groups /opt/nsapps/bravo/node $CLIENT udp --to 192.0.2.10:7001 --count 3 | jq -r '.seen | keys | join(\",\")'"
    in_dut ip rule del from 192.168.10.2 lookup 3200 pref 31000
    in_dut ip rule del from 192.168.20.2 lookup 3201 pref 31000
    if [ "$variant" = ranges ]; then
      # Or loose filtering on the lines only (the kernel uses max(all, interface)).
      in_dut sysctl -qw net.ipv4.conf.vethA.rp_filter=2
      in_dut sysctl -qw net.ipv4.conf.vethB.rp_filter=2
      rpf_try "$variant + rp_filter=2 on the line interfaces only (all=1): bravo" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 4 "$URL"
      rpf_try "$variant + rp_filter=2 on the line interfaces only (all=1): alpha" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 4 "$URL"
    fi
    engine_stop
    topo_down
  done
}

check10() {
  begin check10 "A line without a default route"
  topo_up && servers_up || {
    fail "topology did not come up"
    return
  }
  in_dut ip route del default via 192.168.20.1 dev vethB
  local out code
  out=$(in_dut ip route get 192.0.2.10 oif vethB 2>&1)
  code=$?
  note "\`ip route get 192.0.2.10 oif vethB\` -> exit $code: \`$(tr -s '\n ' ' ' <<< "$out")\`"
  note "\`ip route get 192.0.2.10 oif vethA\` -> \`$(in_dut ip route get 192.0.2.10 oif vethA 2>&1 | tr -s '\n ' ' ')\`"
  if [ "$code" -eq 0 ] && ! grep -q ' via ' <<< "$out"; then
    pass "'ip route get <ip> oif vethB' still succeeds with no default route on B, but shows no 'via' gateway: test for 'via' (or a default route on the device), not the exit code"
  elif [ "$code" -ne 0 ]; then
    pass "'ip route get <ip> oif vethB' fails (exit $code) when B has no default route"
  else
    fail "'ip route get <ip> oif vethB' shows a gateway although B has no default route"
  fi
  note "default routes on vethB: $(in_dut ip route show default dev vethB | wc -l)"
  local dir="$OUT/check10"
  gen "$dir" --log-level info && engine_start "$dir" || return
  local t0 t1 res ec
  t0=$(now_ms)
  res=$(as_app /opt/nsapps/bravo/curl -sS --max-time 10 "$URL" 2>&1)
  ec=$?
  t1=$(now_ms)
  note "bravo (placed on B) with no default route on B: curl exit $ec after $((t1 - t0)) ms: $(tr -s '\n' ' ' <<< "$res")"
  note "neighbour table on vethB: $(in_dut ip neigh show dev vethB | paste -sd ';' -)"
  block "engine log lines about line B" "$(grep -i -E 'line-bb|lane-bb|error|unreachable' "$dir/engine.log" | tail -8)"
  expect_seen "alpha (main line) unaffected" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
  in_dut ip route add default via 192.168.20.1 dev vethB metric 200
  in_dut ip neigh flush dev vethB
  expect_seen "default route back, engine not restarted: bravo" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
  engine_stop
  topo_down
}

check11() {
  begin check11 "Container-like forwarded traffic"
  topo_up && servers_up || {
    fail "topology did not come up"
    return
  }
  ip netns add ctr && ip -n ctr link set lo up
  in_dut ip link add br-ctr type bridge
  in_dut ip addr add 172.18.0.1/24 dev br-ctr
  in_dut ip link set br-ctr up
  link ctr eth0 dut vctr
  in_dut ip link set vctr master br-ctr
  ip -n ctr addr add 172.18.0.2/24 dev eth0
  ip -n ctr route add default via 172.18.0.1
  in_dut sysctl -qw net.ipv4.ip_forward=1
  # What Docker sets up: masquerade the bridge's traffic on its way out.
  in_dut nft add table ip ctrnat
  in_dut nft add chain ip ctrnat post '{ type nat hook postrouting priority 100 ; }'
  in_dut nft add rule ip ctrnat post ip saddr 172.18.0.0/24 oifname != "br-ctr" masquerade
  expect_seen "no engine: container -> 192.0.2.30" 192.0.2.1 ip netns exec ctr curl -s --max-time 5 http://192.0.2.30:8080/
  local variant
  for variant in plain exclude; do
    local dir="$OUT/check11-$variant"
    # Sends 192.0.2.30 to line B, so traffic that passes through the engine shows up as B.
    local opts=(--extra-rule '{"ip_cidr":["192.0.2.30/32"],"action":"route","outbound":"lane-bb"}')
    [ "$variant" = exclude ] && opts+=(--exclude br-ctr)
    gen "$dir" "${opts[@]}" && engine_start "$dir" || continue
    ip netns exec ctr curl -s --max-time 10 "http://192.0.2.30:8080/slow?ms=3000" > /dev/null &
    local slow=$! conns got
    sleep 1.5
    conns=$(api dut /connections | "$NODE" "$ANALYZE" conns --dest-ip 192.0.2.30)
    got=$(ip netns exec ctr curl -s --max-time 5 http://192.0.2.30:8080/)
    wait "$slow"
    if [ "$variant" = plain ]; then
      note "no exclude_interface: container -> ${got:-no answer} (line $(line_of "$got")): $([ "$got" = 192.0.2.2 ] && echo 'its traffic goes through the engine' || echo 'its traffic bypasses the engine')"
    elif [ "$got" = 192.0.2.1 ] && grep -q 'no matching' <<< "$conns"; then
      pass "exclude_interface br-ctr: container -> $got (line A, kernel routing), and the engine saw none of it"
    else
      fail "exclude_interface br-ctr: container -> ${got:-no answer} (line $(line_of "$got"))"
    fi
    block "$variant: the engine's connections to 192.0.2.30" "$conns"
    [ "$variant" = exclude ] && block "ip rule with exclude_interface" "$(ip -n dut rule show)"
    engine_stop
  done
  topo_down
}

check13() {
  begin check13 "Local networks and routers stay on normal routing"
  local variant
  for variant in ranges none own-rules; do
    topo_up && servers_up || {
      fail "$variant: topology did not come up"
      continue
    }
    # Each router serves its own LAN, so it sees dut's LAN address.
    ip netns exec ispA "$NODE" "$HERE/server.mjs" --host 192.168.10.1 > "$OUT/lanA.log" 2>&1 &
    disown
    ip netns exec ispB "$NODE" "$HERE/server.mjs" --host 192.168.20.1 > "$OUT/lanB.log" 2>&1 &
    disown
    wait_for "router A's LAN server" 15 grep -q ready "$OUT/lanA.log"
    wait_for "router B's LAN server" 15 grep -q ready "$OUT/lanB.log"
    local dir="$OUT/check13-$variant"
    # shellcheck disable=SC2046
    gen "$dir" $(variant_flags "$variant") || continue
    variant_setup "$variant"
    engine_start "$dir" || continue
    expect_seen "$variant: alpha (unplaced) -> router A's LAN" 192.168.10.2 as_app /opt/nsapps/alpha/curl -s --max-time 5 http://192.168.10.1:8080/
    expect_seen "$variant: alpha (unplaced) -> router B's LAN" 192.168.20.2 as_app /opt/nsapps/alpha/curl -s --max-time 5 http://192.168.20.1:8080/
    expect_seen "$variant: bravo (placed on B) -> router A's LAN" 192.168.10.2 as_app /opt/nsapps/bravo/curl -s --max-time 5 http://192.168.10.1:8080/
    expect_seen "$variant: alpha (unplaced) -> internet" 192.0.2.1 as_app /opt/nsapps/alpha/curl -s --max-time 5 "$URL"
    expect_seen "$variant: bravo (placed on B) -> internet" 192.0.2.2 as_app /opt/nsapps/bravo/curl -s --max-time 5 "$URL"
    # Did any of that LAN traffic go through the engine?
    local pids=() conns
    as_app /opt/nsapps/alpha/curl -s --max-time 10 "http://192.168.10.1:8080/slow?ms=3000" > /dev/null &
    pids+=($!)
    as_app /opt/nsapps/bravo/curl -s --max-time 10 "http://192.168.20.1:8080/slow?ms=3000" > /dev/null &
    pids+=($!)
    as_app /opt/nsapps/alpha/node "$CLIENT" udp --to 224.0.0.251:5353 --count 2 > /dev/null 2>&1 &
    pids+=($!)
    sleep 1.5
    conns=$(api dut /connections | "$NODE" "$ANALYZE" conns | grep -E '192\.168\.|224\.' || echo '(none to the LANs or multicast)')
    wait "${pids[@]}"
    if grep -q '^(none' <<< "$conns"; then
      pass "$variant: LAN and multicast traffic stayed out of the engine"
    else
      fail "$variant: the engine saw LAN or multicast traffic"
    fi
    block "$variant: engine connections to LAN or multicast addresses" "$conns"
    block "$variant: route lookups" "$(for target in 192.168.10.1 192.168.20.1 224.0.0.251 10.9.9.9 192.0.2.10; do in_dut ip route get "$target" 2>&1 | head -1; done)"
    [ "$variant" != ranges ] && block "$variant: table 3110" "$( (ip -n dut route show table 3110; ip -n dut -6 route show table 3110) | compact)"
    [ "$variant" = own-rules ] && block "own-rules: ip rule" "$(ip -n dut rule show)"
    engine_stop
    topo_down
  done
}

# Goroutines in a Go stack dump, by state and first sing-box/sing-tun frame.
goroutine_kinds() {
  awk '
    function flush() { if (state != "") print state " | " (fn != "" ? fn : top) }
    /^goroutine [0-9]+ .*\[.*\]:$/ {
      flush()
      state = $0; sub(/^[^[]*/, "", state); sub(/:$/, "", state); sub(/, [0-9]+ minutes/, "", state)
      fn = ""; top = ""; next
    }
    state != "" && /^[^\t]/ && !/^created by/ {
      name = $0; sub(/\([^()]*\)$/, "", name)
      if (top == "") top = name
      if (fn == "" && name ~ /sagernet/) fn = name
    }
    END { flush() }
  ' "$1" | sort | uniq -c | sort -rn | head -25
}
# Whole stacks of goroutines that pass through the TUN TCP forwarder or process lookup.
goroutine_stacks() {
  awk '
    function flush() { if (block ~ /Forward|JudgeFlow|PreMatch|FindProcess|findProcess|searcher/ && shown < 4) { print block; shown++ } }
    /^goroutine [0-9]+ .*\[.*\]:$/ { flush(); block = $0; next }
    block != "" { block = block "\n" $0 }
    END { flush() }
  ' "$1" | head -120
}

check14() {
  begin check14 "gvisor + process lookup: hunting handshakes that never finish"
  local round dumped=
  for round in 1 2 3 4 5 6 7 8; do
    topo_up && servers_up || {
      fail "round $round: topology did not come up"
      continue
    }
    # Odd rounds look processes up, even rounds don't.
    local dir="$OUT/check14-round$round" result timeouts mode=lookup opts=(--log-level info)
    if [ $((round % 2)) -eq 0 ]; then
      mode=no-lookup
      opts+=(--no-rules)
    fi
    gen "$dir" "${opts[@]}" && engine_start "$dir" || continue
    result=$(as_app /opt/nsapps/alpha/node "$CLIENT" whoami --to "$WHOAMI" --count 2000 --concurrency 10 --timeout 10000 2>&1 | tail -1)
    timeouts=$(jq -r '.errors.TIMEOUT // 0' <<< "$result" 2>/dev/null)
    note "round $round ($mode): ${timeouts:-?} of 2,000 handshakes never finished; source ports reused in the run: $(jq -r .reusedPorts <<< "$result" 2>/dev/null); stuck: $(jq -c .stalls <<< "$result" 2>/dev/null); the engine logged $(grep -c 'inbound connection from' "$dir/engine.log") inbound connections"
    if [ "${timeouts:-0}" -gt 0 ] && [ -z "$dumped" ]; then
      dumped=1
      kill -QUIT "$SB_PID"
      sleep 3
      info "round $round: dump has $(grep -c '^goroutine ' "$dir/engine.log") goroutines"
      block "round $round: goroutines by state and first sing-box frame" "$(goroutine_kinds "$dir/engine.log")"
      block "round $round: stacks through the forwarder or process lookup" "$(goroutine_stacks "$dir/engine.log")"
      SB_PID=
    fi
    engine_stop
    topo_down
  done
}

apps_setup
summary "## Routing checks: $(. /etc/os-release && echo "$PRETTY_NAME"), $(uname -m), kernel $(uname -r)"
for check in ${CHECKS:-check1 check2 check3 check4 check5 check6 check7 check8 check9 check10 check11 check13}; do
  "$check"
done
CHECK=total
note "$(grep -c '^PASS' "$RESULTS") PASS, $(grep -c '^FAIL' "$RESULTS") FAIL"
finish
exit 0
