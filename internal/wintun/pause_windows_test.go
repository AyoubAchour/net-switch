//go:build windows

package wintun

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These observations never take readMu/writeMu or wait for recovery. Taking a
// blocking session lock here would make a session stall look like a host pause.
// Ring words and counters are individual atomic observations, not a transaction.
type sessionObservation struct {
	Stats          Stats  `json:"stats"`
	RingsAvailable bool   `json:"rings_available"`
	SendHead       uint32 `json:"send_head"`
	SendTail       uint32 `json:"send_tail"`
	ReceiveHead    uint32 `json:"receive_head"`
	ReceiveTail    uint32 `json:"receive_tail"`
}

func observeSession(s *Session) *sessionObservation {
	if s == nil {
		return nil // The DLL does not expose its ring allocation or counters.
	}
	o := &sessionObservation{Stats: s.Stats()}
	if s.mu.TryRLock() {
		if r := s.rings; r != nil {
			o.RingsAvailable = true
			o.SendHead, o.SendTail = r.send.load(0), r.send.load(4)
			o.ReceiveHead, o.ReceiveTail = r.receive.load(0), r.receive.load(4)
		}
		s.mu.RUnlock()
	}
	return o
}

type pauseGap struct {
	Start  int64               `json:"start_qpc"`
	End    int64               `json:"end_qpc"`
	Before *sessionObservation `json:"before,omitempty"`
	After  *sessionObservation `json:"after,omitempty"`
}

func qpcDuration(start, end int64) time.Duration {
	return time.Duration(float64(end-start) * 1e9 / float64(performanceFrequency()))
}

type pauseMonitor struct {
	stop     chan struct{}
	done     sync.WaitGroup
	once     sync.Once
	gaps     [2][]pauseGap // Each sampler owns its slice until both have joined.
	errors   [2]error
	samples  [2]int
	inflight atomic.Int64
	states   []tripObservation // Owned by the native sampler; read only after join.
}

type tripObservation struct {
	Start int64               `json:"trip_start_qpc"`
	At    int64               `json:"sample_qpc"`
	State *sessionObservation `json:"state"`
}

// One heartbeat stays on its own OS thread and uses a native high-resolution
// waitable timer. The other uses Go's timer/scheduler. Only a common gap is
// evidence of a process-wide scheduling pause; a delayed heartbeat alone isn't.
// Both can pause with the Go runtime or host: this cannot distinguish those two.
func startPauseMonitor(t *testing.T, s *Session) *pauseMonitor {
	t.Helper()
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	create := kernel.NewProc("CreateWaitableTimerExW")
	set := kernel.NewProc("SetWaitableTimer")
	must(t, create.Find())
	must(t, set.Find())
	// CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS.
	h, _, err := create.Call(0, 0, 2, 0x1f0003)
	if h == 0 {
		t.Fatalf("create heartbeat timer: %v", err)
	}
	m := &pauseMonitor{stop: make(chan struct{})}
	ready := make(chan struct{}, 2)
	for id := range 2 {
		m.done.Add(1)
		go func() {
			defer m.done.Done()
			if id == 0 {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				defer windows.CloseHandle(windows.Handle(h))
			}
			previous := ticks()
			before := observeSession(s)
			ready <- struct{}{}
			for {
				if id == 0 {
					due := int64(-10000) // Relative 1 ms, in 100 ns units.
					ok, _, err := set.Call(h, uintptr(unsafe.Pointer(&due)), 0, 0, 0, 0)
					if ok == 0 {
						m.errors[id] = fmt.Errorf("arm heartbeat timer: %w", err)
						return
					}
					result, err := windows.WaitForSingleObject(windows.Handle(h), 1000)
					if err != nil || result != windows.WAIT_OBJECT_0 {
						m.errors[id] = fmt.Errorf("heartbeat wait: result=%d error=%v", result, err)
						return
					}
				} else {
					time.Sleep(time.Millisecond)
				}
				now := ticks()
				inflight := m.inflight.Load()
				after := observeSession(s)
				// Keep evidence from INSIDE a delayed reply even when both
				// heartbeats keep running. Ordinary 1 ms samples need no storage.
				if id == 0 && s != nil && inflight != 0 && qpcDuration(inflight, now) > 25*time.Millisecond {
					m.states = append(m.states, tripObservation{inflight, now, after})
				}
				m.samples[id]++
				if qpcDuration(previous, now) > 5*time.Millisecond {
					m.gaps[id] = append(m.gaps[id], pauseGap{previous, now, before, after})
				}
				previous, before = now, after
				select {
				case <-m.stop:
					return
				default:
				}
			}
		}()
	}
	<-ready
	<-ready
	t.Cleanup(func() { m.finish(t) })
	return m
}

func (m *pauseMonitor) finish(t *testing.T) {
	m.once.Do(func() {
		close(m.stop)
		m.done.Wait() // Include the final sample even if the reply beat a sampler.
		for id, err := range m.errors {
			if err != nil {
				t.Errorf("pause sampler %d: %v", id, err)
			}
		}
	})
}

func overlappingGaps(gaps []pauseGap, start, end int64) []pauseGap {
	result := make([]pauseGap, 0)
	for _, gap := range gaps {
		if gap.Start < end && gap.End > start {
			result = append(result, gap)
		}
	}
	return result
}

// Require ONE shared gap to cover the delay to within 5 ms (five sampling
// periods). A merely overlapping pause, many tiny gaps, or a rescued packet
// cannot excuse a session stall. Keep every raw interval for later inspection.
func classifyPause(start, end int64, rescued bool, heartbeat, scheduler []pauseGap) (string, time.Duration) {
	var covered time.Duration
	for _, a := range heartbeat {
		for _, b := range scheduler {
			left, right := max(start, a.Start, b.Start), min(end, a.End, b.End)
			if right > left {
				covered = max(covered, qpcDuration(left, right))
			}
		}
	}
	if !rescued && covered > 0 && qpcDuration(start, end)-covered <= 5*time.Millisecond {
		return "environment_pause", covered
	}
	return "session_stall", covered
}

func TestPauseClassification(t *testing.T) {
	ms := performanceFrequency() / 1000
	gap := func(start, end int64) []pauseGap { return []pauseGap{{Start: start * ms, End: end * ms}} }
	for _, tc := range []struct {
		name      string
		heartbeat []pauseGap
		scheduler []pauseGap
		rescued   bool
		want      string
	}{
		{"no pause", nil, nil, false, "session_stall"},
		{"covered", gap(99, 161), gap(101, 159), false, "environment_pause"},
		{"heartbeat only", gap(99, 161), nil, false, "session_stall"},
		{"scheduler only", nil, gap(99, 161), false, "session_stall"},
		{"small overlap", gap(150, 220), gap(150, 220), false, "session_stall"},
		{"outside", gap(10, 90), gap(10, 90), false, "session_stall"},
		{"unexplained six ms", gap(100, 154), gap(100, 154), false, "session_stall"},
		{"rescue during pause", gap(99, 161), gap(99, 161), true, "session_stall"},
		{"disjoint samplers", gap(99, 130), gap(130, 161), false, "session_stall"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classifyPause(100*ms, 160*ms, tc.rescued, tc.heartbeat, tc.scheduler)
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPerformanceMedian(t *testing.T) {
	values := []float64{52.3, 98.9, 43, 42.7, 41.8, 41.9}
	if got := median(values); got != 42.85 || values[0] != 52.3 {
		t.Fatalf("median=%v samples=%v", got, values)
	}
	// A sustained regression must still cross the unchanged 10% gate.
	if median([]float64{52, 53, 54, 55, 56, 57}) <= median([]float64{45, 46, 45, 46, 45, 46})*1.1 {
		t.Fatal("sustained regression hidden")
	}
}

// Prove the samplers see an actual process-wide pause, not just synthetic
// intervals. Suspend only our disposable child on the hosted CI runner.
func TestWintunPauseMonitor(t *testing.T) {
	requireRunner(t)
	if os.Getenv("NETSWITCH_PAUSE_CHILD") == "1" {
		monitor := startPauseMonitor(t, nil)
		time.Sleep(30 * time.Millisecond)
		fmt.Println("PAUSE_READY")
		_, err := bufio.NewReader(os.Stdin).ReadString('\n')
		must(t, err)
		monitor.finish(t)
		for id, count := range monitor.samples {
			if count < 2 {
				t.Fatalf("sampler %d did not run: %d", id, count)
			}
		}
		data, err := json.Marshal(monitor.gaps)
		must(t, err)
		fmt.Printf("PAUSE_PROBE %s\n", data)
		return
	}
	exe, err := os.Executable()
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestWintunPauseMonitor$", "-test.timeout=10s")
	child.Env = append(os.Environ(), "NETSWITCH_PAUSE_CHILD=1")
	child.Stderr = os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := child.StdoutPipe()
	must(t, err)
	in, err := child.StdinPipe()
	must(t, err)
	defer in.Close()
	must(t, child.Start())
	defer child.Process.Kill()
	reader := bufio.NewReader(out)
	for {
		line, err := reader.ReadString('\n')
		must(t, err)
		if strings.TrimSpace(line) == "PAUSE_READY" {
			break
		}
	}
	// While only the caller is blocked, the child's samplers must keep running.
	liveStart := ticks()
	time.Sleep(80 * time.Millisecond)
	liveEnd := ticks()
	h, err := windows.OpenProcess(0x0800, false, uint32(child.Process.Pid)) // PROCESS_SUSPEND_RESUME
	must(t, err)
	defer windows.CloseHandle(h)
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	suspend, resume := ntdll.NewProc("NtSuspendProcess"), ntdll.NewProc("NtResumeProcess")
	must(t, suspend.Find())
	must(t, resume.Find())
	status, _, _ := suspend.Call(uintptr(h))
	if int32(status) < 0 {
		t.Fatalf("suspend child: %#x", status)
	}
	suspended := true
	defer func() {
		if suspended {
			resume.Call(uintptr(h))
		}
	}()
	start := ticks()
	time.Sleep(120 * time.Millisecond)
	end := ticks()
	status, _, _ = resume.Call(uintptr(h))
	if int32(status) < 0 {
		t.Fatalf("resume child: %#x", status)
	}
	suspended = false
	_, err = fmt.Fprintln(in, "done")
	must(t, err)
	var gaps [2][]pauseGap
	found := false
	for {
		line, err := reader.ReadString('\n')
		if strings.HasPrefix(line, "PAUSE_PROBE ") {
			must(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "PAUSE_PROBE ")), &gaps))
			found = true
		}
		if err != nil {
			break
		}
	}
	must(t, child.Wait())
	if !found {
		t.Fatal("child returned no pause evidence")
	}
	classification, covered := classifyPause(start, end, false, gaps[0], gaps[1])
	if classification != "environment_pause" {
		t.Fatalf("suspended child classified as %s: %+v", classification, gaps)
	}
	if live, _ := classifyPause(liveStart, liveEnd, false, gaps[0], gaps[1]); live != "session_stall" {
		t.Fatal("an idle caller was mistaken for a process-wide pause")
	}
	report(t, map[string]any{"test": "pause_detector_proof", "arch": runtime.GOARCH, "classification": classification, "suspended_ms": qpcDuration(start, end).Seconds() * 1000, "common_gap_ms": covered.Seconds() * 1000})
}
