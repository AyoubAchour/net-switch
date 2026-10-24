package lifecycle_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
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
		t.Run("retirement-failure-exits-and-cleans-capture", func(t *testing.T) {
			for _, trigger := range []string{"control-stop", "service-stop"} {
				t.Run(trigger, func(t *testing.T) {
					c, _ := start(t) // independently verifies real capture and owned journal objects
					hostService, err := service.Query(service.Engine)
					if err != nil || hostService.PID == 0 {
						t.Fatal("host PID", hostService, err)
					}
					hostPID := hostService.PID
					path := filepath.Join(data, "fault-native-retirement")
					if err := os.WriteFile(path, []byte("armed"), 0600); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { os.Remove(path) })
					c.stopLease()
					recovery := newNativeRecoveryTimer()
					stop, cancel := context.WithTimeout(ctx, 15*time.Second)
					defer cancel()
					if trigger == "control-stop" {
						if err := c.call(stop, "stop", nil, nil); err == nil {
							t.Fatal("retirement failure acknowledged as clean stop")
						}
					} else if err := service.Stop(stop, service.Engine); err != nil {
						t.Log("manager stop returned child failure", err)
					}
					wait(t, "failed child exits without another Control request", max(time.Millisecond, 15*time.Second-recovery.elapsed()), func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
					waitNativeCleanup(t, fixture, data, c.instance)
					nativeFreshFlow(t, fixture, ctx, "retirement-failure", recovery, 15*time.Second)
					// The host's exit 1 is a service failure, so the manager's
					// recovery (SCM command / ExecStopPost) republishes this
					// instance's outcome as pending and then complete after the
					// host already wrote complete (see "Reading atomically
					// published outcomes"). Wait for the recovery writer itself:
					// its process is not the host, and its result is final.
					var out host.Outcome
					wait(t, "manager recovery finished for this instance", 15*time.Second, func() bool {
						out, err = host.ReadOutcome(data, c.instance)
						return err == nil && out.RecoveryPID != 0 && out.RecoveryPID != hostPID && (out.State == "complete" || out.State == "failed")
					})
					if err != nil || out.Child == nil || out.Child.Code != 1 || out.Child.Forced || !out.Child.Completed || out.State != "complete" {
						t.Fatalf("failed retirement outcome: child=%+v state=%s error=%v", out.Child, out.State, err)
					}
					t.Logf("NATIVE_RETIREMENT_WRITER host_pid=%d recovery_pid=%d", hostPID, out.RecoveryPID)
					t.Logf("NATIVE_RETIREMENT_FAILURE trigger=%s child=%+v capture_removed=true elapsed=%s", trigger, out.Child, recovery.elapsed())
				})
			}
		})
		t.Run("idle-error-survives-live-lease-backoff", func(t *testing.T) {
			c, _ := start(t)
			nativeMust(t, c, "testFault", map[string]any{"fault": map[string]any{"kind": "idle-error"}}, nil)
			fixture.clean(t)
			for until := time.Now().Add(65 * time.Second); time.Now().Before(until); {
				nativeMust(t, c, "renew", nil, nil)
				var state protocol.Status
				nativeMust(t, c, "status", nil, &state)
				if state.State != "error" || uint32(state.PID) != c.pid {
					t.Fatal("idle error killed or replaced child", state)
				}
				time.Sleep(time.Second)
			}
			rev.N++
			nativeMust(t, c, "start", map[string]any{"revision": rev}, nil)
			fresh, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fresh.Close() })
			nativeEcho(t, fresh, "recovered-idle-error")
			fresh.Close()
			nativeMust(t, c, "stop", nil, nil)
			if err := service.WaitStopped(ctx, service.Engine); err != nil {
				t.Fatal(err)
			}
			t.Logf("NATIVE_IDLE_ERROR child_pid=%d seconds=65 lease_renewed=true recovered=true", c.pid)
		})
		t.Run("forwarding-health-under-load", func(t *testing.T) {
			c, _ := start(t)
			var peers []net.Conn
			for range 8 {
				peer, err := fixture.dial(ctx, "tcp4", fixture.target)
				if err != nil {
					t.Fatal(err)
				}
				peers = append(peers, peer)
				t.Cleanup(func() { peer.Close() })
			}
			var workers sync.WaitGroup
			var bytes atomic.Uint64
			errors := make(chan error, 8)
			loadStarted := time.Now()
			until := loadStarted.Add(60 * time.Second)
			for _, peer := range peers {
				workers.Go(func() {
					marker := strings.Repeat("x", 32<<10)
					payload := "ping " + marker + "\n"
					reader := bufio.NewReaderSize(peer, 40<<10)
					for time.Now().Before(until) {
						peer.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := io.WriteString(peer, payload); err != nil {
							errors <- err
							return
						}
						reply, err := reader.ReadSlice('\n')
						if err == nil {
							err = nativeLoadReply(marker, string(reply), runtime.GOOS == "linux")
						}
						if err != nil {
							errors <- err
							return
						}
						bytes.Add(uint64(len(marker)))
					}
				})
			}
			workers.Wait()
			loadElapsed := time.Since(loadStarted)
			t.Logf("NATIVE_LOAD_FINISHED elapsed=%s echoed_payload_bytes=%d requested_stop=true", loadElapsed, bytes.Load())
			close(errors)
			for err := range errors {
				t.Error("load flow", err)
			}
			nativeMust(t, c, "stop", nil, nil)
			if err := service.WaitStopped(ctx, service.Engine); err != nil {
				t.Fatal(err)
			}
			out, err := host.ReadOutcome(data, c.instance)
			if err != nil || out.Child == nil || out.Child.Forced || !out.Child.Completed || out.Child.HostHealthPasses == 0 || bytes.Load() == 0 || loadElapsed < 60*time.Second {
				t.Fatalf("load incomplete: elapsed=%s bytes=%d child=%+v cleanup=%s error=%v", loadElapsed, bytes.Load(), out.Child, out.State, err)
			}
			t.Logf("NATIVE_HEALTH_LOAD seconds=60 streams=8 echoed_bytes=%d passes=%d failures=%d retries=0", bytes.Load(), out.Child.HostHealthPasses, out.Child.HostHealthFailures)
		})
		for _, hang := range []bool{false, true} {
			name := "slow-start-and-clean-stop"
			if hang {
				name = "starting-hang-is-bounded"
			}
			t.Run(name, func(t *testing.T) {
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
				delay := 33000
				if hang {
					delay = 60000
				}
				path := filepath.Join(data, "fault-native-start-delay")
				if err := lifecycle.Save(path, delay); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(path) })
				call, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				began := time.Now()
				err := c.call(call, "start", map[string]any{"revision": rev}, nil)
				if hang {
					if err == nil {
						t.Fatal("hung start succeeded")
					}
					wait(t, "starting deadline terminates service", max(time.Second, 42*time.Second-time.Since(began)), func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
					out, e := host.ReadOutcome(data, c.instance)
					if e != nil || out.Child == nil || !out.Child.Forced || !strings.Contains(out.Child.Error, "lifecycle deadline exceeded: starting") {
						t.Fatal("wrong start failure", out, e)
					}
					waitNativeCleanup(t, fixture, data, c.instance)
					t.Logf("NATIVE_START_BOUND elapsed=%s", time.Since(began))
					return
				}
				if err != nil {
					t.Fatal("slow legitimate start", err)
				}
				wait(t, "slow start health", 10*time.Second, func() bool { return nativeSupervisorEvent(data, "NATIVE_HEALTH", c.instance) != "" })
				path = filepath.Join(data, "fault-native-stop-delay")
				if err := lifecycle.Save(path, 15000); err != nil {
					t.Fatal(err)
				}
				c.stopLease()
				stop, done := context.WithTimeout(ctx, 25*time.Second)
				defer done()
				if err := c.call(stop, "stop", nil, nil); err != nil {
					t.Fatal("long clean stop", err)
				}
				if err := service.WaitStopped(stop, service.Engine); err != nil {
					t.Fatal(err)
				}
				out, e := host.ReadOutcome(data, c.instance)
				if e != nil || out.Child == nil || out.Child.Forced || !out.Child.Completed || out.Child.Code != 0 {
					t.Fatal("clean stop became crash", out, e)
				}
			})
		}
		t.Run("same-child-routing-restart-health", func(t *testing.T) {
			c, _ := start(t)
			wait(t, "initial forwarding healthy", 10*time.Second, func() bool { return nativeSupervisorEvent(data, "NATIVE_HEALTH", c.instance) != "" })
			previous := nativeOwnershipIDs(t, data, c.instance)
			baseline := len(previous)
			if baseline == 0 {
				t.Fatal("restart has no owned baseline")
			}
			for cycle := 1; cycle <= 2; cycle++ {
				rev.N++ // retain monotonic durable history for following cases
				nativeMust(t, c, "testFault", map[string]any{"fault": map[string]any{"kind": "restart-routing", "revision": rev}}, nil)
				current := nativeOwnershipIDs(t, data, c.instance)
				if len(current) != baseline {
					t.Fatal("restart changed live ownership baseline", cycle, baseline, len(current))
				}
				for id := range current {
					if previous[id] {
						t.Fatal("previous generation journal record was not retired", cycle, id)
					}
				}
				assertNativeOwnedLeftovers(t, data, c.instance)
				assertNativeCapture(t, c.instance, fixture)
				fresh, err := fixture.dial(ctx, "tcp4", fixture.target)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { fresh.Close() })
				nativeEcho(t, fresh, "after-same-child-restart")
				fresh.Close()
				// Remain healthy beyond the complete failure window each time.
				for range 23 {
					time.Sleep(time.Second)
					nativeMust(t, c, "renew", nil, nil)
				}
				t.Logf("NATIVE_RESTART_CYCLE child_pid=%d cycle=%d retired_records=%d live_records=%d", c.pid, cycle, len(previous), len(current))
				previous = current
			}
			nativeMust(t, c, "stop", nil, nil)
			if err := service.WaitStopped(ctx, service.Engine); err != nil {
				t.Fatal(err)
			}
			out, err := host.ReadOutcome(data, c.instance)
			if err != nil || out.Child == nil || out.Child.Forced || out.Child.HostHealthPasses < 40 {
				t.Fatal("health did not survive routing restart", out, err)
			}
			waitNativeCleanup(t, fixture, data, c.instance)
			t.Logf("NATIVE_RESTART_HEALTH child_pid=%d passes=%d", c.pid, out.Child.HostHealthPasses)
		})
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
			wait(t, "host forwarding check passes before fault", 10*time.Second, func() bool {
				return nativeSupervisorEvent(data, "NATIVE_HEALTH", c.instance) != ""
			})
			t.Log(nativeSupervisorEvent(data, "NATIVE_HEALTH", c.instance))
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
				observeUntilNativeExit(t, held, childGone, observer, sent, 43*time.Second, false, data, c.instance)
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
				observeUntilNativeExit(t, held, childGone, observer, sent, bound, true, data, c.instance)
			}
			if mode == "host" && runtime.GOOS == "windows" {
				fixture.clean(t)
				nativeFreshFlow(t, fixture, ctx, mode, recovery, bound)
				resumeHost()
				hostSuspended = false
			}
			wait(t, "supervisor finishes", max(time.Second, bound-recovery.elapsed()), func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
			waitNativeCleanup(t, fixture, data, c.instance)
			for _, event := range []string{"NATIVE_TERMINATE", "NATIVE_TERMINATED", "NATIVE_CLEANED"} {
				line := nativeSupervisorEvent(data, event, c.instance)
				at, ok := nativeSupervisorEventTime(line)
				if ok {
					t.Logf("NATIVE_PHASE event=%s since_fault=%s %s", event, at.Sub(recovery.start), line)
				} else {
					t.Logf("NATIVE_PHASE event=%s host_record_absent=true", event)
				}
			}
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

func nativeLoadReply(marker, reply string, annotated bool) error {
	if annotated {
		if strings.HasPrefix(reply, "pong "+marker+" ") && strings.HasSuffix(reply, "\n") {
			return nil
		}
	} else if reply == "ping "+marker+"\n" {
		return nil
	}
	return fmt.Errorf("load fixture reply mismatch: annotated=%t reply_bytes=%d", annotated, len(reply))
}

func TestNativeLoadFixtureProtocols(t *testing.T) {
	marker := strings.Repeat("x", 32<<10)
	for _, tc := range []struct {
		reply     string
		annotated bool
		valid     bool
	}{
		{"ping " + marker + "\n", false, true},
		{"pong " + marker + " 203.0.113.1:5000\n", true, true},
		{"pong short 203.0.113.1:5000\n", true, false},
		{"ping " + marker, false, false},
		{strings.Repeat("\x00", 32<<10), true, false},
	} {
		reader := bufio.NewReaderSize(strings.NewReader(tc.reply), 40<<10)
		reply, err := reader.ReadSlice('\n')
		if err == nil {
			err = nativeLoadReply(marker, string(reply), tc.annotated)
		}
		if (err == nil) != tc.valid {
			t.Fatal("fixture protocol validation", tc.annotated, tc.valid, err)
		}
	}
}

func observeUntilNativeExit(t *testing.T, conn net.Conn, gone func() bool, observer nativeSocketObservation, sent time.Time, bound time.Duration, expectExit bool, data, instance string) {
	t.Helper()
	began := time.Now()
	gaveUp := false
	var terminalAt time.Time
	var terminalProblem error
	for time.Since(began) < bound && !gone() {
		if gaveUp {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		var b [1]byte
		n, err := conn.Read(b[:])
		observed := time.Now()
		kind, problem := stallReadDisposition(n, err, observer.verifyGiveUp)
		if problem != nil {
			observer.sample("terminal-read")
			t.Logf("NATIVE_HELD_END at=%s since_send=%s bytes=%d error=%v child_gone=%t", observed.UTC().Format(time.RFC3339Nano), observed.Sub(sent), n, err, gone())
			// Logs may be delivered asynchronously. Compare the event's own
			// timestamp, never the time its log line finally became readable.
			if n != 0 {
				t.Error("data delivered during stall", problem)
			}
			terminalAt, terminalProblem = observed, problem
			gaveUp = true // continue measuring kill and cleanup even on failure
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
	if terminalProblem != nil {
		decision := nativeSupervisorEvent(data, "NATIVE_TERMINATE", instance)
		if !nativeTerminationPrecedes(decision, terminalAt) {
			t.Error("held flow ended before proved termination", terminalProblem, decision)
		}
	}
}

func nativeSupervisorEvent(data, event, instance string) string {
	for _, name := range []string{"NetSwitchEngine.log", "NetSwitchEngine.log.old"} {
		b, _ := os.ReadFile(filepath.Join(data, name))
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, event+" instance="+instance+" ") {
				return line
			}
		}
	}
	return ""
}
func nativeTerminationPrecedes(line string, observed time.Time) bool {
	at, ok := nativeSupervisorEventTime(line)
	return ok && !at.After(observed)
}
func nativeSupervisorEventTime(line string) (time.Time, bool) {
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "at=") {
			at, err := time.Parse(time.RFC3339Nano, strings.TrimPrefix(field, "at="))
			return at, err == nil
		}
	}
	return time.Time{}, false
}

func TestNativeHeldFlowRequiresEarlierTermination(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		line string
		want bool
	}{
		{"", false}, {"at=invalid", false},
		{"at=" + now.Add(time.Nanosecond).Format(time.RFC3339Nano), false},
		{"at=" + now.Add(-time.Nanosecond).Format(time.RFC3339Nano), true},
	} {
		if nativeTerminationPrecedes(test.line, now) != test.want {
			t.Fatal(test)
		}
	}
}
