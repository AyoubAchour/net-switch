//go:build windows

package wintun

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
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
	stop       chan struct{}
	done       sync.WaitGroup
	once       sync.Once
	gaps       [2][]pauseGap // Each sampler owns its slice until both have joined.
	errors     [2]error
	samples    [2]int
	timestamps [2][]int64 // Retain ordinary samples too: a missing gap is not proof of progress.
	inflight   atomic.Int64
	states     []tripObservation // Owned by the native sampler; read only after join.
}

const pauseSamplePeriod = time.Millisecond

// A gap longer than two periods missed at least one expected sample. The old
// 5 ms storage cutoff discarded short missed samples before the classifier
// could intersect them with the other sampler. This is independent of the
// classifier's unchanged 5 ms total unexplained-time allowance.
func missedPauseSample(start, end int64) bool {
	return qpcDuration(start, end) > 2*pauseSamplePeriod
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
	for id := range 2 {
		m.timestamps[id] = make([]int64, 0, 65536)
	}
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
			m.timestamps[id] = append(m.timestamps[id], previous)
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
					time.Sleep(pauseSamplePeriod)
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
				m.timestamps[id] = append(m.timestamps[id], now)
				if missedPauseSample(previous, now) {
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

// Include the samples bracketing the trip. Together with every sample inside
// it, these reconstruct all intervals, including those below the gap cutoff.
func overlappingSamples(samples []int64, start, end int64) []int64 {
	left := sort.Search(len(samples), func(i int) bool { return samples[i] >= start })
	right := sort.Search(len(samples), func(i int) bool { return samples[i] >= end })
	if left > 0 {
		left--
	}
	if right < len(samples) {
		right++
	}
	return samples[left:right]
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

// Count only time covered by BOTH samplers, clipped to this reply. A burst may
// contain several pauses separated by real scheduling progress. Merge their
// intersections before summing so neither a split nor a duplicate interval
// changes the evidence. The unexplained remainder must still be at most 5 ms
// (five sampling periods), and a rescue can never be exempted.
func classifyPause(start, end int64, rescued bool, heartbeat, scheduler []pauseGap) (string, time.Duration) {
	type interval struct{ start, end int64 }
	var common []interval
	for _, a := range heartbeat {
		for _, b := range scheduler {
			left, right := max(start, a.Start, b.Start), min(end, a.End, b.End)
			if right > left {
				common = append(common, interval{left, right})
			}
		}
	}
	sort.Slice(common, func(i, j int) bool { return common[i].start < common[j].start })
	var coveredTicks int64
	if len(common) != 0 {
		merged := common[0]
		for _, next := range common[1:] {
			if next.start <= merged.end {
				merged.end = max(merged.end, next.end)
			} else {
				coveredTicks += merged.end - merged.start
				merged = next
			}
		}
		coveredTicks += merged.end - merged.start
	}
	covered := qpcDuration(0, coveredTicks)
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
		{"two pauses", append(gap(99, 130), gap(133, 161)...), gap(99, 161), false, "environment_pause"},
		{"split observation", append(gap(99, 130), gap(130, 161)...), gap(99, 161), false, "environment_pause"},
		{"duplicates cannot inflate coverage", append(gap(100, 130), gap(100, 130)...), gap(99, 161), false, "session_stall"},
		{"unexplained time between pauses", append(gap(99, 125), gap(135, 161)...), gap(99, 161), false, "session_stall"},
		{"rescue across pauses", append(gap(99, 130), gap(133, 161)...), gap(99, 161), true, "session_stall"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classifyPause(100*ms, 160*ms, tc.rescued, tc.heartbeat, tc.scheduler)
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	t.Run("recorded ARM64 pause burst", func(t *testing.T) {
		// Job 118309008902, sequence 87713, QPC at 10 MHz. The old
		// longest-gap calculation explained only 45.3379 of 52.5101 ms.
		// The union explains 49.0729 ms, leaving 3.4372 ms unexplained.
		// Scale offsets so this test also works on other QPC frequencies.
		qpc := func(recorded int64) int64 {
			return (recorded - 3619320455) * performanceFrequency() / 10000000
		}
		heartbeat := []pauseGap{
			{Start: qpc(3617782743), End: qpc(3619357805)},
			{Start: qpc(3619390857), End: qpc(3619850339)},
		}
		scheduler := []pauseGap{
			{Start: qpc(3617773167), End: qpc(3619321255)},
			{Start: qpc(3619321255), End: qpc(3619844236)},
		}
		classification, covered := classifyPause(qpc(3619320455), qpc(3619845556), false, heartbeat, scheduler)
		if classification != "environment_pause" || covered < 49072*time.Microsecond || covered > 49074*time.Microsecond {
			t.Fatalf("recorded pause burst: %s, covered %s", classification, covered)
		}
	})
}

func TestPauseClassificationBorderlineTrace(t *testing.T) {
	// Job 118761509687, sequence 174468. These are all the logged endpoints;
	// no samples were retained inside the 4.6227 ms hole.
	qpc := func(recorded int64) int64 {
		return (recorded - 3786075803) * performanceFrequency() / 10000000
	}
	start, end := qpc(3786091692), qpc(3786734914)
	heartbeat := []pauseGap{{Start: qpc(3786075803), End: qpc(3786730140)}}
	scheduler := []pauseGap{
		{Start: qpc(3786075928), End: qpc(3786320714)},
		{Start: qpc(3786366941), End: qpc(3786733534)},
	}
	classification, covered := classifyPause(start, end, false, heartbeat, scheduler)
	if classification != "session_stall" || covered < 59221*time.Microsecond || covered > 59223*time.Microsecond {
		t.Fatalf("incomplete recorded trace: %s, covered %s", classification, covered)
	}
	// Both completions below could have produced exactly that old log. Only a
	// recorded missed sample may fill the hole; never merge nearby gaps blindly.
	for _, tc := range []struct {
		name    string
		samples []int64
		want    string
	}{
		{"one missed sample", []int64{3786320714, 3786366941}, "environment_pause"},
		{"four ordinary samples", []int64{3786320714, 3786332271, 3786343828, 3786355385, 3786366941}, "session_stall"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gaps := append([]pauseGap(nil), scheduler...)
			for i := 1; i < len(tc.samples); i++ {
				a, b := qpc(tc.samples[i-1]), qpc(tc.samples[i])
				if missedPauseSample(a, b) {
					gaps = append(gaps, pauseGap{Start: a, End: b})
				}
			}
			got, coverage := classifyPause(start, end, false, heartbeat, gaps)
			if got != tc.want {
				t.Fatalf("got %s, want %s; covered %s", got, tc.want, coverage)
			}
			if tc.want == "environment_pause" && (coverage < 63844*time.Microsecond || coverage > 63846*time.Microsecond) {
				t.Fatalf("missed sample coverage: %s", coverage)
			}
			t.Logf("completion=%s classification=%s covered=%s unexplained=%s", tc.name, got, coverage, qpcDuration(start, end)-coverage)
		})
	}
}

func TestPauseClassificationSampling(t *testing.T) {
	ms := performanceFrequency() / 1000
	var regular, missed []pauseGap
	for i := int64(0); i < 60; i++ {
		a, b := i*ms, (i+1)*ms
		if missedPauseSample(a, b) {
			regular = append(regular, pauseGap{Start: a, End: b})
		}
	}
	for i := int64(0); i < 60; i += 3 {
		a, b := i*ms, (i+3)*ms
		if missedPauseSample(a, b) {
			missed = append(missed, pauseGap{Start: a, End: b})
		}
	}
	whole := []pauseGap{{Start: 0, End: 60 * ms}}
	for _, tc := range []struct {
		name string
		a, b []pauseGap
		want string
	}{
		{"regular samples are not pauses", regular, regular, "session_stall"},
		{"one sampler alone misses samples", whole, regular, "session_stall"},
		{"short shared missed samples are retained", whole, missed, "environment_pause"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classifyPause(0, 60*ms, false, tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	samples := []int64{0, 10, 20, 30, 40}
	for _, tc := range []struct {
		start, end int64
		want       string
	}{
		{12, 28, "[10 20 30]"},
		{10, 30, "[0 10 20 30]"},
		{-10, 50, "[0 10 20 30 40]"},
		{50, 60, "[40]"},
	} {
		if got := fmt.Sprint(overlappingSamples(samples, tc.start, tc.end)); got != tc.want {
			t.Fatalf("samples for %d..%d: %s, want %s", tc.start, tc.end, got, tc.want)
		}
	}
}

const (
	sessionDelayWindow   = 80 * time.Millisecond
	sessionDelayAttempts = 3
	// Healthy CI runs (2026-10-21/22) replied in 80.4-81.7 ms, 0.4-1.7 ms over
	// the injected block. Five milliseconds keeps ordinary jitter on time, so a
	// late reply - the evidence this test exists to judge - is never retried.
	sessionDelayLateAllowance = 5 * time.Millisecond
	// A working sampler reaches 51-71 samples per ~80 ms window (0.63-0.89 of
	// the nominal 1 ms cadence). Half is a wide margin below that and still
	// catches one that lost most of the window.
	pauseSamplerFloorRatio = 0.5
)

type sessionDelayAttempt struct {
	Number  int
	Start   int64
	End     int64
	Samples [2]int
	Gaps    [2][]pauseGap // Complete monitor evidence; the log clips it to the window.
	Queued  *sessionObservation
}

func sessionDelaySampleFloor(window time.Duration) int {
	return int(pauseSamplerFloorRatio * float64(window) / float64(pauseSamplePeriod))
}

// measureSessionDelay performs one injection: the real reader lock is held
// while a real packet queues, then released. Latency and both samplers' counts
// and gaps are captured here, before any judgement, so an under-sampled window
// is still fully reported. The echo is stopped and restarted because a parked
// ReadBatch holds readMu, which this test needs to take.
func measureSessionDelay(t *testing.T, f *fixture, s *Session, c *net.UDPConn, payload []byte, number int) *sessionDelayAttempt {
	t.Helper()
	f.stopEcho()
	s.readMu.Lock()
	locked := true
	defer func() {
		if locked {
			s.readMu.Unlock()
		}
	}()
	f.startEcho(t)
	monitor := startPauseMonitor(t, s)
	must(t, c.SetDeadline(time.Now().Add(2*time.Second)))
	start := ticks()
	monitor.inflight.Store(start)
	_, err := c.Write(payload)
	must(t, err)
	for {
		state := observeSession(s)
		if state.RingsAvailable && state.SendTail != state.SendHead {
			break
		}
		if elapsed(start) > time.Second {
			t.Fatal("injection precondition failed: no packet queued behind reader lock")
		}
		time.Sleep(time.Millisecond)
	}
	queued := ticks()
	for elapsed(queued) < sessionDelayWindow {
		time.Sleep(time.Millisecond)
	}
	before := observeSession(s)
	if !before.RingsAvailable || before.SendTail == before.SendHead {
		t.Fatal("injection lost its queued packet before releasing the lock")
	}
	s.readMu.Unlock()
	locked = false
	reply := make([]byte, 128)
	n, err := c.Read(reply)
	must(t, err)
	end := ticks()
	monitor.inflight.Store(0)
	if string(reply[:n]) != string(payload) {
		t.Fatal("injected trip payload mismatch")
	}
	monitor.finish(t)
	return &sessionDelayAttempt{Number: number, Start: start, End: end, Samples: monitor.samples, Gaps: monitor.gaps, Queued: before}
}

// Hold the real session's reader lock while a real packet is queued. Only that
// reader is blocked: both pause samplers must continue to run. No production
// hooks, retries or classifier exemptions are involved.
//
// A sampler that loses most of the window has not measured anything, so that
// attempt is logged in full and redone on a fresh window. A late reply is
// evidence and is judged on the attempt that produced it, never retried.
func TestWintunSessionDelay(t *testing.T) {
	requireRunner(t)
	f := newFixture(t, "ours", 0)
	s := f.io.(*Session)
	c := udpSocket(t)
	defer c.Close()
	payload := []byte("deliberately blocked session reader")

	var attempt *sessionDelayAttempt
	logged := make([]string, 0, sessionDelayAttempts)
	for number := 1; number <= sessionDelayAttempts; number++ {
		attempt = measureSessionDelay(t, f, s, c, payload, number)
		latency := qpcDuration(attempt.Start, attempt.End)
		floor := sessionDelaySampleFloor(latency)
		report(t, map[string]any{"test": "session_delay_attempt", "arch": runtime.GOARCH, "attempt": number, "ms": latency.Seconds() * 1000, "samples": attempt.Samples, "sample_floor": floor, "heartbeat_gaps": overlappingGaps(attempt.Gaps[0], attempt.Start, attempt.End), "scheduler_gaps": overlappingGaps(attempt.Gaps[1], attempt.Start, attempt.End)})
		entry := fmt.Sprintf("attempt %d: %d/%d samples (floor %d), reply %.1f ms", number, attempt.Samples[0], attempt.Samples[1], floor, latency.Seconds()*1000)
		logged = append(logged, entry)
		if latency > sessionDelayWindow+sessionDelayLateAllowance {
			break
		}
		if attempt.Samples[0] >= floor && attempt.Samples[1] >= floor {
			break
		}
		t.Logf("pause sampler starved (test instrument, not the session; retrying): %s", entry)
	}
	latency := qpcDuration(attempt.Start, attempt.End)
	floor := sessionDelaySampleFloor(latency)
	if (attempt.Samples[0] < floor || attempt.Samples[1] < floor) && latency <= sessionDelayWindow+sessionDelayLateAllowance {
		t.Fatalf("pause sampler starved on %d attempts; the test instrument lost the windows, the session reply arrived on time in every attempt: %s", sessionDelayAttempts, strings.Join(logged, "; "))
	}
	classification, covered := classifyPause(attempt.Start, attempt.End, false, attempt.Gaps[0], attempt.Gaps[1])
	report(t, map[string]any{"test": "session_delay_proof", "arch": runtime.GOARCH, "attempts": attempt.Number, "classification": classification, "ms": latency.Seconds() * 1000, "common_pause_ms": covered.Seconds() * 1000, "samples": attempt.Samples, "queued_before_release": attempt.Queued, "state_at_reply": observeSession(s)})
	if classification != "session_stall" {
		t.Fatalf("real blocked session was exempted: %s", classification)
	}
}

func TestPerformanceMedian(t *testing.T) {
	values := []float64{52.3, 98.9, 43, 42.7, 41.8, 41.9}
	if got := median(values); got != 42.85 || values[0] != 52.3 {
		t.Fatalf("median=%v samples=%v", got, values)
	}
	// Each pair shares its runner conditions. Pooling the implementations
	// separately would report 90/200 = 0.45 here, instead of 0.90.
	ratios, err := pairedRatios([]float64{90, 90, 180}, []float64{100, 200, 200})
	if err != nil || median(ratios) != 0.90 {
		t.Fatalf("matched ratios=%v err=%v", ratios, err)
	}
	// Alternating slow/fast conditions must not hide a sustained regression.
	baseline := []float64{107, 170, 107, 170, 107, 170, 107, 170, 107, 170, 107, 170}
	for _, scale := range []float64{0.89, 1.11} {
		ours := make([]float64, len(baseline))
		for i := range ours {
			ours[i] = baseline[i] * scale
		}
		ratios, err := pairedRatios(ours, baseline)
		if err != nil || math.Abs(median(ratios)-scale) > 1e-12 {
			t.Fatalf("sustained regression hidden: %v %v", ratios, err)
		}
	}
	for _, invalid := range [][]float64{nil, {100}, {100, 0}, {100, -1}, {100, math.NaN()}, {100, math.Inf(1)}} {
		if _, err := pairedRatios([]float64{100, 100}, invalid); err == nil {
			t.Fatalf("invalid reference accepted: %v", invalid)
		}
		if _, err := pairedRatios(invalid, []float64{100, 100}); err == nil {
			t.Fatalf("invalid own sample accepted: %v", invalid)
		}
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
	report(t, map[string]any{"test": "pause_detector_proof", "arch": runtime.GOARCH, "classification": classification, "suspended_ms": qpcDuration(start, end).Seconds() * 1000, "common_pause_ms": covered.Seconds() * 1000})
}
