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
	armed, registered, largest := 0, 0, 0
	var total udpReadinessMetrics
	for i := range p.shards {
		s := &p.shards[i]
		s.mu.Lock()
		registered += len(s.watches)
		largest = max(largest, len(s.watches))
		for watch := range s.watches {
			if watch.events != 0 {
				armed++
			}
		}
		total.merge(s.metrics)
		s.mu.Unlock()
	}
	return map[string]any{"measured": p.capture, "registered": registered, "armed": armed,
		"timingUpperUS": udpTimingUS, "metrics": total, "shards": udpShardCount,
		"shardCapacity": udpShardCapacity, "largestShard": largest, "waiters": udpWaiters}
}

func (m *udpTiming) merge(other udpTiming) {
	m.Count += other.Count
	m.Nanos += other.Nanos
	m.MaxNanos = max(m.MaxNanos, other.MaxNanos)
	for i := range m.Buckets {
		m.Buckets[i] += other.Buckets[i]
	}
}

func (m *udpReadinessMetrics) merge(other udpReadinessMetrics) {
	m.Arm.merge(other.Arm)
	m.ArmLockWait.merge(other.ArmLockWait)
	m.BuildRows.merge(other.BuildRows)
	m.Poll.merge(other.Poll)
	m.Disarm.merge(other.Disarm)
	m.Callbacks.merge(other.Callbacks)
	m.WaitReturns += other.WaitReturns
	m.PollRows += other.PollRows
	m.ReadyRows += other.ReadyRows
	m.ZeroReadyPolls += other.ZeroReadyPolls
	m.SetEvents += other.SetEvents
	m.MaxPollRows = max(m.MaxPollRows, other.MaxPollRows)
}
