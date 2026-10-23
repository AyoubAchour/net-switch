package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// fakeDesktopControl answers the desktop's requests over an in-memory pipe.
func fakeDesktopControl(t *testing.T, conn io.ReadWriteCloser, connected chan<- struct{}) {
	t.Helper()
	defer conn.Close()
	scan := bufio.NewScanner(conn)
	for scan.Scan() {
		var request map[string]any
		if err := json.Unmarshal(scan.Bytes(), &request); err != nil {
			t.Error(err)
			return
		}
		reply := map[string]any{"id": request["id"]}
		switch request["method"] {
		case "status":
			reply["result"] = map[string]any{"owner": Owner{User: CurrentUser(), Name: "Owner"}, "routing": "off"}
		case "signin":
			reply["error"] = "routing intent could not be saved"
		case "session":
			reply["result"] = map[string]any{"token": "token", "url": "http://127.0.0.1:1/", "ownerName": "Owner"}
		case "desktop-connect":
			reply["result"] = nil
			select {
			case connected <- struct{}{}:
			default:
			}
		case "desktop-poll":
			reply["result"] = []any{}
		default:
			reply["error"] = "unexpected method"
		}
		b, _ := json.Marshal(reply)
		if _, err := conn.Write(append(b, '\n')); err != nil {
			return
		}
	}
}

func TestRejectedSignInKeepsDesktopRunning(t *testing.T) {
	connected := make(chan struct{}, 1)
	shown := make(chan string, 4)
	oldDial, oldShow := dialIPC, showRejectedSignIn
	t.Cleanup(func() { dialIPC, showRejectedSignIn = oldDial, oldShow })
	showRejectedSignIn = func(message string) { shown <- message }
	dialIPC = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		client, server := net.Pipe()
		go fakeDesktopControl(t, server, connected)
		return &localipc.Conn{ReadWriteCloser: client, Peer: localipc.Peer{User: "S-1-5-18"}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Desktop(ctx, false) }()
	select {
	case message := <-shown:
		if !strings.Contains(message, "routing intent could not be saved") {
			t.Fatal("the refusal reason was not shown", message)
		}
	case err := <-done:
		t.Fatal("desktop exited after a rejected sign-in", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the rejected sign-in was not shown")
	}
	select {
	case <-connected:
	case err := <-done:
		t.Fatal("desktop exited instead of staying connected", err)
	case <-time.After(5 * time.Second):
		t.Fatal("desktop did not stay connected after the refusal")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func dialAll(t *testing.T, address string, n int) []net.Conn {
	t.Helper()
	var conns []net.Conn
	for range n {
		c, err := net.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	return conns
}

// The owner's connection must not wait for one identity lookup per earlier
// connection: everything queued behind a slow lookup is resolved together.
func TestHTTPAdmissionResolvesQueuedConnectionsInOneBatch(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var mu sync.Mutex
	var batches []int
	resolve := func(tuples []localipc.TCPTuple) []localipc.TCPIdentity {
		mu.Lock()
		batches = append(batches, len(tuples))
		first := len(batches) == 1
		mu.Unlock()
		if first {
			<-release // a lookup slowed by a huge table or churn
		}
		out := make([]localipc.TCPIdentity, len(tuples))
		for i, tuple := range tuples {
			if tuple.Client == nil || tuple.Server == nil {
				t.Error("tuple lacks its addresses", tuple)
			}
			out[i].User = "owner"
		}
		return out
	}
	l := newHTTPListener(raw, &connectionLimits{owner: "owner", users: map[string]int{}}, func(string) {}, resolve)
	defer l.Close()
	dialAll(t, raw.Addr().String(), 1)
	waitFor(t, "first lookup", func() bool { mu.Lock(); defer mu.Unlock(); return len(batches) == 1 })
	dialAll(t, raw.Addr().String(), 20)
	waitFor(t, "connections queued behind the slow lookup", func() bool { l.mu.Lock(); defer l.mu.Unlock(); return len(l.queue) == 20 })
	close(release)
	for range 21 {
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if c.(*admittedHTTPConn).user != "owner" {
			t.Fatal("identity lost", c)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 2 || batches[1] != 20 {
		t.Fatal("queued connections were not resolved as one batch", batches)
	}
}

// A fast churn must not fill the queue while the resolver sits out the
// interval: once a full batch waits, the lookup starts at once.
func TestHTTPAdmissionLooksUpEarlyWhenABatchWaits(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var batches []int
	resolve := func(tuples []localipc.TCPTuple) []localipc.TCPIdentity {
		mu.Lock()
		batches = append(batches, len(tuples))
		mu.Unlock()
		out := make([]localipc.TCPIdentity, len(tuples))
		for i := range out {
			out[i].User = "owner"
		}
		return out
	}
	limits := &connectionLimits{owner: "owner", users: map[string]int{}}
	l := newHTTPListenerEvery(raw, limits, func(string) {}, resolve, time.Hour)
	defer l.Close()
	dialAll(t, raw.Addr().String(), 1)
	if _, err := l.Accept(); err != nil {
		t.Fatal(err)
	}
	// The owner pool admits 32; the rest are refused, which is fine here:
	// only the timing of the second lookup matters.
	dialAll(t, raw.Addr().String(), httpLookupBatch)
	waitFor(t, "a full batch is looked up without waiting out the interval", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(batches) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	if batches[1] < httpLookupBatch {
		t.Fatal("early lookup ran before a full batch waited", batches)
	}
}

// A "batch waiting" signal left over from a batch that an earlier lookup
// took without waiting must not let a single later connection skip the gap.
func TestHTTPAdmissionIgnoresStaleBatchSignals(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const interval = 200 * time.Millisecond
	release := make(chan struct{})
	var mu sync.Mutex
	var starts []time.Time
	var sizes []int
	resolve := func(tuples []localipc.TCPTuple) []localipc.TCPIdentity {
		mu.Lock()
		starts = append(starts, time.Now())
		sizes = append(sizes, len(tuples))
		first := len(starts) == 1
		mu.Unlock()
		if first {
			<-release
		}
		out := make([]localipc.TCPIdentity, len(tuples))
		for i := range out {
			out[i].User = "unresolved" // refused beyond two; only timing matters
		}
		return out
	}
	l := newHTTPListenerEvery(raw, &connectionLimits{owner: "owner", users: map[string]int{}}, func(string) {}, resolve, interval)
	defer l.Close()
	dialAll(t, raw.Addr().String(), 1)
	waitFor(t, "first lookup", func() bool { mu.Lock(); defer mu.Unlock(); return len(starts) == 1 })
	// While the first lookup is held past the interval, a full batch queues
	// and signals. The next lookup then starts without waiting, takes the
	// batch, and leaves that signal behind.
	dialAll(t, raw.Addr().String(), httpLookupBatch)
	waitFor(t, "batch queued", func() bool { return l.queued() == httpLookupBatch })
	time.Sleep(interval + 20*time.Millisecond)
	close(release)
	waitFor(t, "batch looked up", func() bool { mu.Lock(); defer mu.Unlock(); return len(starts) == 2 })
	dialAll(t, raw.Addr().String(), 1)
	waitFor(t, "single connection looked up", func() bool { mu.Lock(); defer mu.Unlock(); return len(starts) == 3 })
	mu.Lock()
	defer mu.Unlock()
	if sizes[1] != httpLookupBatch || sizes[2] != 1 {
		t.Fatal("unexpected batches", sizes)
	}
	if gap := starts[2].Sub(starts[1]); gap < interval-20*time.Millisecond {
		t.Fatal("a stale batch signal let a single connection skip the gap", gap)
	}
}

// Churn must not buy one machine-wide snapshot per connection: lookups are
// at least httpLookupInterval apart, and connections wait in one batch.
func TestHTTPAdmissionSpacesLookupsUnderChurn(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var starts []time.Time
	resolve := func(tuples []localipc.TCPTuple) []localipc.TCPIdentity {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		out := make([]localipc.TCPIdentity, len(tuples))
		for i := range out {
			out[i].User = "owner"
		}
		return out
	}
	l := newHTTPListener(raw, &connectionLimits{owner: "owner", users: map[string]int{}}, func(string) {}, resolve)
	defer l.Close()
	for range 30 {
		dialAll(t, raw.Addr().String(), 1)
		if _, err := l.Accept(); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < httpLookupInterval-5*time.Millisecond {
			t.Fatal("lookups closer than the interval", gap)
		}
	}
	if len(starts) > 30 {
		t.Fatal("more lookups than connections", len(starts))
	}
}

func TestHTTPAdmissionRefusesOverLimitUsersAndDrainsOnClose(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(tuples []localipc.TCPTuple) []localipc.TCPIdentity {
		out := make([]localipc.TCPIdentity, len(tuples))
		for i := range out {
			out[i].User = localipc.LowIntegrity + "owner"
		}
		return out
	}
	l := newHTTPListener(raw, &connectionLimits{owner: "owner", users: map[string]int{}}, func(string) {}, resolve)
	conns := dialAll(t, raw.Addr().String(), 6)
	clientIndex := make(map[string]int, len(conns))
	for i, c := range conns {
		clientIndex[c.LocalAddr().String()] = i
	}
	// Keep the admitted connections referenced: netFD has a finalizer that
	// closes its socket, and the client read below would then see EOF from a
	// connection the server still holds.
	var admitted []net.Conn
	admittedClients := make(map[int]bool, 2)
	for range 2 {
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if user := c.(*admittedHTTPConn).user; user == "owner" {
			t.Fatal("a low-integrity owner process used owner capacity")
		}
		i, ok := clientIndex[c.RemoteAddr().String()]
		if !ok {
			t.Fatal("accepted connection does not belong to a dialed client", c.RemoteAddr())
		}
		admitted = append(admitted, c)
		admittedClients[i] = true
	}
	defer func() {
		for _, c := range admitted {
			c.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	refused := 0
	for i, c := range conns {
		c.SetReadDeadline(deadline)
		_, err := c.Read(make([]byte, 1))
		eof := errors.Is(err, io.EOF)
		if eof {
			refused++
		}
		if admittedClients[i] {
			if eof {
				t.Fatalf("admitted connection %d was closed by the server", i)
			}
			continue
		}
		if !eof {
			t.Fatalf("connection %d over the limit stayed open (read error %v)", i, err)
		}
	}
	runtime.KeepAlive(admitted)
	if refused != 4 {
		t.Fatal("public per-user limit was not applied", refused)
	}
	l.Close()
	if _, err := l.Accept(); err == nil {
		t.Fatal("closed listener accepted")
	}
}

func waitFor(t *testing.T, label string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout: " + label)
}

type testClock struct{ ns atomic.Int64 }

func (c *testClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }
func newTestClock() *testClock {
	c := &testClock{}
	c.ns.Store(time.Unix(1000, 0).UnixNano())
	return c
}

func TestPowerPauseIsBounded(t *testing.T) {
	clock := newTestClock()
	var p powerPause
	p.set(true, clock.now())
	clock.advance(maxPowerPause - time.Second)
	if p.expired(clock.now()) || !p.on {
		t.Fatal("pause ended early")
	}
	clock.advance(time.Second)
	if !p.expired(clock.now()) || p.on {
		t.Fatal("pause outlived its bound")
	}
	if p.expired(clock.now()) {
		t.Fatal("an ended pause expired twice")
	}
	p.set(false, clock.now())
	clock.advance(time.Hour)
	if p.expired(clock.now()) {
		t.Fatal("no pause cannot expire")
	}
}

// A suspend whose resume is lost must not keep new starts paused forever.
func TestLostResumeUnpausesStartsAfterTheBound(t *testing.T) {
	clock := newTestClock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	events := service.NewEventQueue()
	power := make(chan bool, 4)
	logs := make(chan string, 16)
	var queries atomic.Int32
	go func() {
		defer close(done)
		runSessionEventsWithClock(ctx, events, "owner", NewRemote(ctx, func(string) {}), func(paused bool) { power <- paused },
			func() error { t.Error("a lost resume cleared routing intent"); return nil },
			func(s string) { logs <- s },
			func(string, uint32) (bool, error) { queries.Add(1); return true, nil }, clock.now, 5*time.Millisecond)
	}()
	events.Publish(service.Event{Suspend: true})
	if got := <-power; !got {
		t.Fatal("suspend did not pause starts")
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case got := <-power:
		t.Fatal("pause ended before its bound", got)
	default:
	}
	before := queries.Load()
	clock.advance(maxPowerPause)
	select {
	case got := <-power:
		if got {
			t.Fatal("bound re-paused instead of resuming")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pause outlived its bound")
	}
	if queries.Load() <= before {
		t.Fatal("owner session was not rechecked before allowing starts")
	}
	select {
	case line := <-logs:
		if !strings.Contains(line, "no resume notification") {
			t.Fatal(line)
		}
	default:
		t.Fatal("bound was not logged")
	}
}

func TestSessionQueryOutageLogsAreRateLimited(t *testing.T) {
	clock := newTestClock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	var mu sync.Mutex
	var lines []string
	var failing atomic.Bool
	failing.Store(true)
	var queries atomic.Int32
	go func() {
		defer close(done)
		runSessionEventsWithClock(ctx, service.NewEventQueue(), "owner", NewRemote(ctx, func(string) {}), func(bool) {}, func() error { return nil },
			func(s string) { mu.Lock(); lines = append(lines, s); mu.Unlock() },
			func(string, uint32) (bool, error) {
				queries.Add(1)
				if failing.Load() {
					return false, errors.New("WTS unavailable")
				}
				return true, nil
			}, clock.now, time.Millisecond)
	}()
	count := func(text string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, line := range lines {
			if strings.Contains(line, text) {
				n++
			}
		}
		return n
	}
	waitFor(t, "many failed queries", func() bool { return queries.Load() > 100 })
	if n := count("unavailable"); n != 1 {
		t.Fatal("outage was not rate limited", n)
	}
	clock.advance(sessionLogInterval)
	waitFor(t, "periodic summary", func() bool { return count("unavailable") == 2 })
	mu.Lock()
	last := lines[len(lines)-1]
	mu.Unlock()
	if !strings.Contains(last, "failures not logged since the previous report: ") || strings.Contains(last, "report: 0)") {
		t.Fatal("summary does not count suppressed failures", last)
	}
	failing.Store(false)
	waitFor(t, "recovery line", func() bool { return count("available again") == 1 })
}
