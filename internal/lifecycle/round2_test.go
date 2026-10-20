package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func TestReservedConnectionsRemainAvailableDuringAttack(t *testing.T) {
	l := &connectionLimits{owner: "owner", users: map[string]int{}}
	for i := range 8 {
		user := string(rune('a' + i))
		if !l.take(user) || !l.take(user) || l.take(user) {
			t.Fatal("per-user cap", user)
		}
	}
	if l.take("another-attacker") {
		t.Fatal("public capacity not bounded")
	}
	for _, user := range []string{"owner", "0", "S-1-5-18"} {
		if !l.take(user) {
			t.Fatal("attacker held the reserved slot", user)
		}
	}
}

func fakeRemote(t *testing.T, version string) (*Remote, *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewRemote(ctx, func(string) {})
	attachments := &atomic.Int32{}
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		server, client := net.Pipe()
		t.Cleanup(func() { server.Close(); client.Close() })
		go func() {
			defer server.Close()
			scan := bufio.NewScanner(server)
			for scan.Scan() {
				var req map[string]any
				_ = json.Unmarshal(scan.Bytes(), &req)
				var value any = true
				switch req["method"] {
				case "hello":
					value = map[string]any{"version": version, "engineInstanceId": "same-instance", "capabilities": []string{"singbox-adapter-v1"}, "adapterSnapshot": ce.Snapshot{Status: "on", Policy: ce.Policy{AppLines: apps.Pins{}}}}
				case "attach":
					value = map[string]any{"epoch": attachments.Add(1)}
				case "stats":
					value = ce.Snapshot{Status: "on", Instance: "same-instance", Policy: ce.Policy{AppLines: apps.Pins{}}}
				}
				if json.NewEncoder(server).Encode(map[string]any{"id": req["id"], "result": value}) != nil {
					return
				}
			}
		}()
		return &localipc.Conn{ReadWriteCloser: client}, nil
	}
	r.queryService = func(string) (service.Status, error) { return service.Status{PID: 123, Running: true}, nil }
	return r, attachments
}

func TestTransportFailureReattachesWithoutEngineFailure(t *testing.T) {
	r, attaches := fakeRemote(t, buildinfo.String())
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	rpc.Close()
	deadline := time.Now().Add(time.Second)
	for attaches.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if attaches.Load() != 2 {
		t.Fatal("transport did not reattach")
	}
	if s := r.Snapshot(); s.Status != "on" || s.Instance != "same-instance" || s.FailureID != "" {
		t.Fatal("live engine counted as failed", s)
	}
}

func TestOldStoppedQueryCannotFailReplacement(t *testing.T) {
	r, _ := fakeRemote(t, buildinfo.String())
	original := r.dial
	var refusing atomic.Bool
	r.dial = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		if refusing.Load() {
			return nil, errors.New("old connection is gone")
		}
		return original(ctx, e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	r.queryService = func(string) (service.Status, error) {
		close(entered)
		<-release
		return service.Status{Stopped: true}, nil
	}
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	old := r.rpc
	r.mu.Unlock()
	refusing.Store(true)
	r.disconnect(old, errors.New("old transport"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("recovery did not query service")
	}
	refusing.Store(false)
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		busy := r.recovering
		r.mu.Unlock()
		if !busy {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if s := r.Snapshot(); s.Status != "on" || s.FailureID != "" {
		t.Fatal("stale stopped result failed a healthy attachment", s)
	}
}

func TestOneFailureIdentityPerEngineInstance(t *testing.T) {
	r, _ := fakeRemote(t, buildinfo.String())
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	r.Fail(errors.New("start failed"))
	id := r.Snapshot().FailureID
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) { return nil, errors.New("gone") }
	r.queryService = func(string) (service.Status, error) { return service.Status{Stopped: true}, nil }
	r.disconnect(rpc, errors.New("process exited after failed start"))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		recovering := r.recovering
		r.mu.Unlock()
		if !recovering {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if s := r.Snapshot(); id == "" || s.FailureID != id {
		t.Fatal("one attempt produced multiple failures", id, s)
	}
}

func TestVersionMismatchRefusedBeforeAttach(t *testing.T) {
	r, count := fakeRemote(t, "incompatible")
	if err := r.Attach(r.ctx, false); err == nil || count.Load() != 0 {
		t.Fatal("incompatible engine received attach", err)
	}
}

func TestForgetLaneDoesNotPerformIPC(t *testing.T) {
	r, _ := fakeRemote(t, buildinfo.String())
	r.snapshot = ce.Snapshot{Status: "on", Policy: ce.Policy{Lanes: map[string]string{"a": "b"}}}
	done := make(chan struct{})
	go func() { r.ForgetLane("a"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state-lock invalidation blocked on IPC")
	}
	if _, ok := r.Snapshot().Policy.Lanes["a"]; ok {
		t.Fatal("local lane was not invalidated")
	}
}

func TestOwnerLogoffAndHybridResumeWaitForSignIn(t *testing.T) {
	for _, test := range []struct {
		event   service.Event
		present bool
	}{
		{service.Event{Logoff: true, Session: 7}, false},
		{service.Event{Resume: true}, false},
		{service.Event{Resume: true}, true},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		events := make(chan service.Event)
		ready, done, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var queries, stops atomic.Int32
		r := NewRemote(ctx, func(string) {})
		query := func(owner string, excluded uint32) (bool, error) {
			if owner != "owner" || excluded != ^uint32(0) {
				t.Error("callback session ID was used as authority")
			}
			if queries.Add(1) == 1 {
				close(ready)
			}
			return test.present, nil
		}
		go func() {
			defer close(done)
			runSessionEvents(ctx, events, "owner", r, func() error {
				if stops.Add(1) == 1 {
					close(stopped)
				}
				return nil
			}, func(string) {}, query)
		}()
		<-ready
		events <- test.event
		if test.present {
			deadline := time.Now().Add(3 * time.Second)
			for queries.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		} else {
			select {
			case <-stopped:
			case <-time.After(3 * time.Second):
				cancel()
				<-done
				t.Fatal("production session loop did not stop routing")
			}
		}
		cancel()
		<-done
		if queries.Load() < 2 || test.present && stops.Load() != 0 || !test.present && stops.Load() != 1 {
			t.Fatal("wrong session transition", queries.Load(), stops.Load())
		}
		if test.event.Resume {
			r.mu.Lock()
			grace := r.wakeGrace
			r.mu.Unlock()
			if !grace.After(time.Now()) {
				t.Fatal("Control resume did not reach Remote.Wake")
			}
		}
	}
}

func TestSeveralOwnerDesktopSessions(t *testing.T) {
	d := &DesktopBridge{}
	d.Connect("console", 1)
	d.Connect("rdp", 2)
	d.Disconnect("rdp")
	if d.PID() != 1 {
		t.Fatal("closing RDP evicted the console desktop")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.Call(ctx, "installed-apps", nil); done <- err }()
	var batch []DesktopWork
	for len(batch) == 0 && ctx.Err() == nil {
		batch = d.Poll("console")
		time.Sleep(time.Millisecond)
	}
	if len(batch) != 1 {
		t.Fatal("remaining owner session received no work")
	}
	d.Complete("rdp", batch[0].ID, nil, "")
	select {
	case <-done:
		t.Fatal("other session supplied the result")
	default:
	}
	d.Complete("console", batch[0].ID, []any{}, "")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
