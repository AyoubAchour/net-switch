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
	for _, event := range []service.Event{{Logoff: true, Session: 7}, {Resume: true}} {
		stops := 0
		handleSessionEvent(event, "owner", func(owner string, exclude uint32) (bool, error) {
			if owner != "owner" || event.Logoff && exclude != 7 {
				t.Fatal("wrong OS session checked")
			}
			return false, nil
		}, func() error { stops++; return nil }, func(string) {})
		if stops != 1 {
			t.Fatal("routing survived the last owner sign-out/hybrid resume")
		}
	}
	stops := 0
	handleSessionEvent(service.Event{Resume: true}, "owner", func(string, uint32) (bool, error) { return true, nil }, func() error { stops++; return nil }, func(string) {})
	if stops != 0 {
		t.Fatal("ordinary resume tore down routing")
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
