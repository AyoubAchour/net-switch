//go:build windows

package winengine

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/journal"
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
	started := time.Now()
	return func() { p.record(name, time.Since(started)) }
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
	timings *phaseTimings
}

func (s measuredJournalStore) Records() ([]journal.Record, error) {
	defer s.timings.begin("journal.read")()
	return s.Store.Records()
}
func (s measuredJournalStore) Append(record journal.Record) error {
	defer s.timings.begin("journal." + record.Phase)()
	return s.Store.Append(record)
}

type measuredTun struct {
	*wintun.Session
	timings *phaseTimings
}

func (s *measuredTun) Close() error {
	defer s.timings.begin("tun.session.close")()
	return s.Session.Close()
}
