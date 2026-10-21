package lifecycle

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/localipc"
)

// A connection that falls into the unresolved pool keeps its reason in the
// log, and an oversized table is told apart from a broken lookup.
func TestHTTPAdmissionLogsWhyIdentitiesAreUnresolved(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logs []string
	logf := func(s string) { mu.Lock(); logs = append(logs, s); mu.Unlock() }
	calls := 0
	resolve := func(tuples []localipc.TCPTuple) []localipc.TCPIdentity {
		calls++
		out := make([]localipc.TCPIdentity, len(tuples))
		for i := range out {
			if calls == 1 {
				out[i].Err = localipc.ErrTCPTableLimit
			} else {
				out[i].Err = errors.New("access denied")
			}
		}
		return out
	}
	l := newHTTPListener(raw, &connectionLimits{owner: "owner", users: map[string]int{}}, logf, resolve)
	defer l.Close()
	for range 2 {
		dialAll(t, raw.Addr().String(), 1)
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if user := c.(*admittedHTTPConn).user; user != "unresolved" {
			t.Fatal("a failed lookup was not treated as unresolved", user)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	var table, failed bool
	for _, line := range logs {
		table = table || strings.Contains(line, "lookup skipped: TCP owner table exceeds limit")
		failed = failed || strings.Contains(line, "lookup failed: access denied")
	}
	if !table || !failed {
		t.Fatal("unresolved reasons were not logged separately", logs)
	}
}
