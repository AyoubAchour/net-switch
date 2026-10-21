//go:build windows

package winengine

import "time"

// Hosted diagnostics only. All updates occur under the readiness lock; the
// release packet path does not read a clock or update these histograms.
var udpTimingUS = [...]uint64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 1000000, ^uint64(0)}

type udpTiming struct {
	Count, Nanos, MaxNanos uint64
	Buckets                [len(udpTimingUS)]uint64
}

func (m *udpTiming) add(elapsed time.Duration) {
	n := uint64(max(elapsed, 0))
	m.Count++
	m.Nanos += n
	m.MaxNanos = max(m.MaxNanos, n)
	for i, upper := range udpTimingUS {
		if n/1000 <= upper {
			m.Buckets[i]++
			break
		}
	}
}

type udpReadinessMetrics struct {
	Arm, ArmLockWait, BuildRows, Poll, Disarm, Callbacks        udpTiming
	WaitReturns, PollRows, ReadyRows, ZeroReadyPolls, SetEvents uint64
	MaxPollRows                                                 uint64
}

func (p *udpReadiness) stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	armed := 0
	for watch := range p.watches {
		if watch.events != 0 {
			armed++
		}
	}
	return map[string]any{"measured": p.capture, "registered": len(p.watches), "armed": armed,
		"timingUpperUS": udpTimingUS, "metrics": p.metrics}
}
