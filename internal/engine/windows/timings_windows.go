//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/wintun"
)

type phaseTiming struct {
	Calls      uint64 `json:"calls"`
	TotalNanos uint64 `json:"totalNanos"`
	MaxNanos   uint64 `json:"maxNanos"`
}
type phaseTimings struct {
	mu     sync.Mutex
	values map[string]phaseTiming
	trace  bool
}

func (p *phaseTimings) record(name string, elapsed time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	value := p.values[name]
	value.Calls++
	value.TotalNanos += uint64(max(elapsed, 0))
	value.MaxNanos = max(value.MaxNanos, uint64(max(elapsed, 0)))
	p.values[name] = value
}
func (p *phaseTimings) begin(name string) func() {
	started := winclock.Now()
	finish := func() { p.record(name, winclock.Since(started)) }
	if p == nil || !p.trace {
		return finish
	}
	switch name {
	case "engine.stop.tcp-join", "engine.stop.stack-join", "journal.read", "cleanup.total":
		// One bounded snapshot while a measured hosted phase is still active.
		// This diagnostic never runs on users' machines.
		timer := time.AfterFunc(10*time.Millisecond, func() {
			b := make([]byte, 256<<10)
			n := runtime.Stack(b, true)
			record, _ := json.Marshal(map[string]any{"operation": "stop-wait", "phase": name, "stacks": string(b[:n])})
			log.Printf("WINDOWS LIFECYCLE %s", record)
		})
		return func() { timer.Stop(); finish() }
	default:
		return finish
	}
}
func (p *phaseTimings) snapshot() map[string]phaseTiming {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]phaseTiming, len(p.values))
	for name, value := range p.values {
		out[name] = value
	}
	return out
}
func (p *phaseTimings) report(instance, operation string, err error) {
	result := map[string]any{"instance": instance, "operation": operation, "phases": p.snapshot()}
	if err != nil {
		result["error"] = err.Error()
	}
	b, _ := json.Marshal(result)
	log.Printf("WINDOWS LIFECYCLE %s", b)
}

// The shared journal stays unchanged. These timings separate its durable file
// work from the Windows API calls inside each journaled operation.
type measuredJournalStore struct {
	journal.Store
	timings       *phaseTimings
	beforeRemoved func() error
}

func (s measuredJournalStore) commitRemovals(records []journal.Record) error {
	if len(records) != 0 && records[0].Phase == "removed" && s.beforeRemoved != nil {
		return s.beforeRemoved()
	}
	return nil
}
func (s measuredJournalStore) Records() ([]journal.Record, error) {
	defer s.timings.begin("journal.read")()
	return s.Store.Records()
}
func (s measuredJournalStore) Append(record journal.Record) error {
	if err := s.commitRemovals([]journal.Record{record}); err != nil {
		return err
	}
	defer s.timings.begin("journal." + record.Phase)()
	return s.Store.Append(record)
}
func (s measuredJournalStore) AppendBatch(records []journal.Record) error {
	if len(records) == 0 {
		return nil
	}
	if err := s.commitRemovals(records); err != nil {
		return err
	}
	defer s.timings.begin("journal." + records[0].Phase)()
	if batch, ok := s.Store.(journal.BatchStore); ok {
		return batch.AppendBatch(records)
	}
	for _, record := range records {
		if err := s.Store.Append(record); err != nil {
			return err
		}
	}
	return nil
}

type measuredTun struct {
	*wintun.Session
	timings *phaseTimings
	trace   *packetTrace
}

func (s *measuredTun) ReadPacket(ctx context.Context, packet []byte) (int, error) {
	n, err := s.Session.ReadPacket(ctx, packet)
	if n > 0 && n <= len(packet) {
		s.trace.record("from-app", packet[:n], 0, 0, err)
	}
	return n, err
}

func (s *measuredTun) WriteBatch(packets [][]byte) (int, error) {
	n, err := s.Session.WriteBatch(packets)
	if s.trace != nil {
		for _, packet := range packets {
			s.trace.record("to-app", packet, n, len(packets), err)
		}
	}
	return n, err
}

func (s *measuredTun) Close() error {
	err := s.Session.Close()
	s.timings.record("tun.session.close", time.Duration(s.Session.Stats().CloseNanos))
	return err
}
