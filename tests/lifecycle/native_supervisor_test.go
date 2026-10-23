package lifecycle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func nativeSupervisorCases(t *testing.T, ctx context.Context, fixture tunFixture, data string, rev policy.Revision, faults bool) {
	start := func(t *testing.T) (*nativeClient, net.Conn) {
		if err := service.Start(ctx, service.Engine); err != nil {
			t.Fatal(err)
		}
		c, _ := attachNative(t, ctx, data)
		t.Cleanup(func() {
			stop, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := service.Stop(stop, service.Engine); err != nil {
				t.Error(err)
			}
		})
		nativeMust(t, c, "start", map[string]any{"revision": rev}, nil)
		held, err := fixture.dial(ctx, "tcp4", fixture.target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { held.Close() })
		nativeEcho(t, held, "supervised-capture-established")
		assertNativeCapture(t, c.instance, fixture)
		assertNativeOwnedLeftovers(t, data, c.instance)
		return c, held
	}
	if faults {
		t.Run("startup-death-before-readiness", func(t *testing.T) {
			path := filepath.Join(data, "fault-native-startup-exit")
			if err := os.WriteFile(path, []byte("armed"), 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path)
			if err := service.Start(ctx, service.Engine); err == nil {
				t.Fatal("dead child made installed service ready")
			}
			wait(t, "failed startup exits", 20*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
			fixture.clean(t)
		})
		t.Run("slow-relay-and-log-readers", func(t *testing.T) {
			path := filepath.Join(data, "fault-native-log-sink")
			if err := os.WriteFile(path, []byte("armed"), 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path)
			c, held := start(t)
			var hit struct {
				PID int `json:"pid"`
			}
			wait(t, "real host log sink is blocked", 5*time.Second, func() bool { return lifecycle.Read(path+".hit", &hit) == nil })
			manager, _ := service.Query(service.Engine)
			if hit.PID != int(manager.PID) {
				t.Fatal("wrong log fault domain", hit, manager)
			}
			nativeMust(t, c, "testFault", map[string]any{"fault": map[string]any{"kind": "log-flood"}}, nil)
			slow, err := localipc.DialNativeEngine(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
			if err != nil {
				t.Fatal(err)
			}
			defer slow.Close()
			var requests atomic.Int32
			go func() {
				for i := range 256 {
					b, _ := json.Marshal(map[string]any{"id": fmt.Sprint(i), "method": "stats", "engineInstanceId": c.instance, "epoch": c.epoch})
					if _, err := slow.Write(append(b, '\n')); err != nil {
						return
					}
					requests.Add(1)
				}
			}()
			for range 4 {
				nativeMust(t, c, "renew", nil, nil)
				nativeEcho(t, held, "flow-with-slow-readers")
				time.Sleep(time.Second)
			}
			if requests.Load() < 16 {
				t.Fatal("slow-reader precondition never filled ordinary reply slots", requests.Load())
			}
			drained := make(chan int64, 1)
			go func() { n, _ := io.Copy(io.Discard, slow); drained <- n }()
			select {
			case bytes := <-drained:
				if bytes == 0 {
					t.Fatal("slow peer received no real replies")
				}
				t.Logf("NATIVE_RELAY slow_peer_closed=true received=%d admitted=%d legitimate_renewals=true", bytes, requests.Load())
			case <-time.After(3 * time.Second):
				t.Fatal("slow relay did not close within bound")
			}
			nativeMust(t, c, "stop", nil, nil)
			if err := service.WaitStopped(ctx, service.Engine); err != nil {
				t.Fatal(err)
			}
			out, err := host.ReadOutcome(data, c.instance)
			if err != nil || out.Child == nil || out.Child.HostLogsDropped == 0 || out.Child.HostHealthPasses < 2 || !out.Child.Completed || out.Child.Code != 0 {
				t.Fatal("slow logs blocked health or clean completion", out, err)
			}
			t.Logf("NATIVE_BACKPRESSURE host_logs_dropped=%d successful_forwarding_checks=%d clean_completion=true", out.Child.HostLogsDropped, out.Child.HostHealthPasses)
		})
	}
	modes := []string{"whole-child", "host", "host-and-child"}
	if faults {
		modes = []string{"read-pump"}
	}
	for _, mode := range modes {
		t.Run("control-absent-"+mode, func(t *testing.T) {
			c, held := start(t)
			manager, err := service.Query(service.Engine)
			if err != nil {
				t.Fatal(err)
			}
			childGone, _, resumeChild := pinNativeChild(t, c.pid)
			hostGone, _, resumeHost := pinNativeChild(t, manager.PID)
			childSuspended, hostSuspended := false, false
			observer := nativeSocketObserver(t, held)
			observer.sample("before-supervisor-fault")
			c.stopLease()
			nativeMust(t, c, "renew", nil, nil)
			c.rpc.Close()
			t.Cleanup(func() {
				if hostSuspended && !hostGone() {
					resumeHost()
				}
				if childSuspended && !childGone() {
					resumeChild()
				}
			})
			recovery := newNativeRecoveryTimer()
			sent := time.Now()
			if mode == "read-pump" {
				arm := filepath.Join(data, "fault-native-forwarding")
				if err := os.WriteFile(arm, []byte("armed"), 0600); err != nil {
					t.Fatal(err)
				}
				sent = time.Now()
				if _, err := fmt.Fprint(held, "ping watchdog-stalled\n"); err != nil {
					t.Fatal(err)
				}
				var hit struct {
					PID   int `json:"pid"`
					Bytes int `json:"bytes"`
				}
				wait(t, "child read-pump stall hit", 5*time.Second, func() bool { return lifecycle.Read(filepath.Join(data, "native-forwarding-hit.json"), &hit) == nil })
				if hit.PID != int(c.pid) || hit.Bytes <= 0 {
					t.Fatal("wrong stalled process", hit, c.pid)
				}
			} else {
				if mode != "host" {
					suspendAdapter(t, c.pid)
					childSuspended = true
				}
				if mode != "whole-child" {
					suspendAdapter(t, manager.PID)
					hostSuspended = true
				}
				if mode != "host" {
					sent = time.Now()
					if _, err := fmt.Fprint(held, "ping watchdog-stalled\n"); err != nil {
						t.Fatal(err)
					}
				} else {
					nativeEcho(t, held, "forwarding-with-supervisor-suspended")
				}
			}
			bound := 28 * time.Second
			if mode == "host" && runtime.GOOS == "windows" {
				bound = 42 * time.Second
			}
			if mode == "host-and-child" && runtime.GOOS == "windows" {
				observeUntilNativeExit(t, held, childGone, observer, sent, 43*time.Second, false)
				if childGone() || hostGone() {
					t.Fatal("accepted simultaneous-suspension case unexpectedly ended")
				}
				assertNativeCapture(t, c.instance, fixture)
				t.Log("NATIVE_ACCEPTED_GAP host_and_child_suspended=true control_absent=true capture_present_after=43s platform=windows")
				recovery = newNativeRecoveryTimer()
				resumeHost()
				hostSuspended = false
				resumeChild()
				childSuspended = false
				bound = 12 * time.Second
			} else if mode == "host" {
				wait(t, "child exits despite suspended host", bound, childGone)
			} else {
				observeUntilNativeExit(t, held, childGone, observer, sent, bound, true)
			}
			if mode == "host" && runtime.GOOS == "windows" {
				fixture.clean(t)
				nativeFreshFlow(t, fixture, ctx, mode, recovery, bound)
				resumeHost()
				hostSuspended = false
			}
			wait(t, "supervisor finishes", max(time.Second, bound-recovery.elapsed()), func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
			waitNativeCleanup(t, fixture, data, c.instance)
			nativeFreshFlow(t, fixture, ctx, mode, recovery, bound)
			if mode == "whole-child" || mode == "read-pump" {
				out, err := host.ReadOutcome(data, c.instance)
				if err != nil || out.Child == nil || !out.Child.Forced || out.Child.Completed {
					t.Fatal("watchdog kill was not classified as forced failure", out, err)
				}
			}
			t.Logf("NATIVE_SUPERVISION fault=%s control_absent=true fresh_flow_after=%s bound=%s host_pid=%d child_pid=%d", mode, recovery.elapsed(), bound, manager.PID, c.pid)
			// The host never respawns. This explicit controller restart is a new
			// manager start, retaining the unchanged 70 s wanted-routing bound.
			if mode == "whole-child" || mode == "read-pump" {
				if err := service.Start(ctx, service.Engine); err != nil {
					t.Fatal(err)
				}
				restarted, _ := attachNative(t, ctx, data)
				if restarted.instance == c.instance || restarted.pid == c.pid {
					t.Fatal("restart did not create a new fenced child")
				}
				nativeMust(t, restarted, "start", map[string]any{"revision": rev}, nil)
				nativeFreshFlow(t, fixture, ctx, mode+"-controller-restart", recovery, 70*time.Second)
				nativeMust(t, restarted, "stop", nil, nil)
				if err := service.WaitStopped(ctx, service.Engine); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func observeUntilNativeExit(t *testing.T, conn net.Conn, gone func() bool, observer nativeSocketObservation, sent time.Time, bound time.Duration, expectExit bool) {
	t.Helper()
	began := time.Now()
	gaveUp := false
	for time.Since(began) < bound && !gone() {
		if gaveUp {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		var b [1]byte
		n, err := conn.Read(b[:])
		if gone() {
			break
		} // termination may reset the old stream; record only before it
		kind, problem := stallReadDisposition(n, err, observer.verifyGiveUp)
		if problem != nil {
			t.Fatal(problem)
		}
		if kind == "os-give-up" {
			gaveUp = true
			observer.sample("OS-give-up-before-recovery")
			t.Logf("NATIVE_OS_GIVE_UP since_send=%s", time.Since(sent))
		}
	}
	if expectExit && !gone() {
		t.Fatal("watchdog did not terminate child inside bound", bound)
	}
}
