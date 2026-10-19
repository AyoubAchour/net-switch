//go:build linux

package suite

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
)

// Evidence the cases gather on their own, independent of what apps report:
// the fake internet's records, which processes hold a socket and in which
// cgroups, kernel settings read back while the engine runs, and the path MTU
// the kernel learned.

// Records reads everything that has reached the fake internet. Failing to
// read it, or its server having stopped, stops the case: "nothing arrived"
// must never be the result of a missing log.
func (e *Env) Records() []inet.Record {
	if err := e.Net.Healthy(); err != nil {
		e.T.Fatalf("%v", err)
	}
	recs, err := inet.ReadRecords(e.Net.EventsPath())
	if err != nil {
		e.T.Fatalf("%v", err)
	}
	return recs
}

// WaitRecords polls the records until match is satisfied or timeout passes.
func (e *Env) WaitRecords(timeout time.Duration, match func([]inet.Record) bool) ([]inet.Record, bool) {
	deadline := time.Now().Add(timeout)
	for {
		recs := e.Records()
		if match(recs) {
			return recs, true
		}
		if time.Now().After(deadline) || e.Ctx().Err() != nil {
			return recs, false
		}
		e.Sleep(100 * time.Millisecond)
	}
}

// Select picks records.
func Select(recs []inet.Record, keep func(inet.Record) bool) []inet.Record {
	var out []inet.Record
	for _, r := range recs {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

// Tagged keeps records of a kind whose data carries a token ("T:<token>:...").
func Tagged(kind, token string) func(inet.Record) bool {
	return func(r inet.Record) bool { return r.Kind == kind && strings.HasPrefix(r.Data, "T:"+token+":") }
}

// FromLine keeps records of a kind the server saw coming from a line, to a
// port, within [from, to] (Unix ms; 0 means open).
func FromLine(kind string, line engine.LineID, port uint16, from, to int64) func(inet.Record) bool {
	return func(r inet.Record) bool {
		if r.Kind != kind || topo.LineOfText(r.Src) != line || (from > 0 && r.T < from) || (to > 0 && r.T > to) {
			return false
		}
		return port == 0 || strings.HasSuffix(r.Dst, ":"+strconv.Itoa(int(port)))
	}
}

// RecordLines maps records to the lines the server saw them come from.
func RecordLines(recs []inet.Record) map[engine.LineID]int {
	out := map[engine.LineID]int{}
	for _, r := range recs {
		id := topo.LineOfText(r.Src)
		if id == "" {
			id = "?"
		}
		out[id]++
	}
	return out
}

// Holder is a process holding a socket.
type Holder struct {
	Pid    int
	Exe    string
	Cgroup string
}

func (h Holder) String() string {
	return fmt.Sprintf("%d %s (%s)", h.Pid, filepath.Base(filepath.Dir(h.Exe))+"/"+filepath.Base(h.Exe), h.Cgroup)
}

// Holders lists every process with the socket open, by scanning /proc as root.
func (e *Env) Holders(inode uint64) []Holder {
	want := fmt.Sprintf("socket:[%d]", inode)
	procs, err := os.ReadDir("/proc")
	if err != nil {
		e.T.Fatalf("reading /proc: %v", err)
	}
	var out []Holder
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && link == want {
				out = append(out, Holder{Pid: pid, Exe: exeOf(pid), Cgroup: CgroupOf(pid)})
				break
			}
		}
	}
	return out
}

func exeOf(pid int) string {
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return strings.TrimSuffix(exe, " (deleted)")
}

// CgroupOf is a process's cgroup v2 path.
func CgroupOf(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path
		}
	}
	return ""
}

var readyPattern = regexp.MustCompile(`socket:(\d+) pid:(\d+)`)

// ParseReady reads a "ready socket:<inode> pid:<pid> ..." line.
func (e *Env) ParseReady(line string) (inode uint64, pid int) {
	m := readyPattern.FindStringSubmatch(line)
	if m == nil {
		e.T.Fatalf("not a ready line: %q", line)
	}
	inode, _ = strconv.ParseUint(m[1], 10, 64)
	pid, _ = strconv.Atoi(m[2])
	return inode, pid
}

// HolderPids is the sorted pids of holders.
func HolderPids(hs []Holder) []int {
	var out []int
	for _, h := range hs {
		out = append(out, h.Pid)
	}
	slices.Sort(out)
	return out
}

// SysctlDUT reads a kernel setting on the PC.
func (e *Env) SysctlDUT(key string) string {
	out, err := e.Net.R.In(e.Ctx(), topo.DUT, "sysctl", "-n", key)
	if err != nil {
		e.T.Fatalf("%v", err)
	}
	return strings.TrimSpace(out)
}

var mtuPattern = regexp.MustCompile(`\bmtu (\d+)\b`)

// LearnedMTU is the smallest path MTU the PC's kernel has learned towards dst
// over a line, from either way a socket on that line can be routed (by its
// source address, or bound to the interface); 0 when none was learned.
func (e *Env) LearnedMTU(dst string, line engine.LineID) int {
	l := topo.Line(line)
	src := l.Addr4.Addr().String()
	if strings.Contains(dst, ":") {
		src = l.Addr6.Addr().String()
	}
	best := 0
	for _, args := range [][]string{{"route", "get", dst, "from", src}, {"route", "get", dst, "oif", l.Iface}} {
		out, err := e.Net.R.IP(e.Ctx(), topo.DUT, args...)
		e.T.Logf("ip route %s: %s %v", strings.Join(args[1:], " "), strings.Join(strings.Fields(out), " "), err)
		if err != nil {
			continue
		}
		if m := mtuPattern.FindStringSubmatch(out); m != nil {
			if mtu, _ := strconv.Atoi(m[1]); best == 0 || mtu < best {
				best = mtu
			}
		}
	}
	return best
}
