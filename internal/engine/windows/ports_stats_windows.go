//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	winplatform "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"golang.org/x/sys/windows"
)

type portTemplate = winplatform.TCPPortSetting

type portDiagnostics struct {
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
	wait    sync.WaitGroup
	count   atomic.Uint64
	lastLog atomic.Int64
	mu      sync.Mutex
	state   string
	config  []portTemplate
	err     string
}

func newPortDiagnostics() *portDiagnostics {
	ctx, cancel := context.WithCancel(context.Background())
	state := "notRequested"
	if !diagnosticProcesses {
		state = "disabled"
	}
	return &portDiagnostics{ctx: ctx, cancel: cancel, state: state}
}

func portLimit(err error) bool {
	return errors.Is(err, windows.WSAENOBUFS) || errors.Is(err, windows.WSAEADDRINUSE)
}

func (p *portDiagnostics) observe(err error) {
	if p == nil || !portLimit(err) {
		return
	}
	total := p.count.Add(1)
	second := time.Now().Unix()
	old := p.lastLog.Load()
	if old != second && p.lastLog.CompareAndSwap(old, second) {
		log.Printf("Windows TCP port pool exhausted; refused=%d; bound socket failed: %v", total, err)
	}
	if !diagnosticProcesses {
		return
	}
	p.once.Do(func() {
		p.mu.Lock()
		p.state = "loading"
		p.mu.Unlock()
		p.wait.Go(p.load)
	})
}

func (p *portDiagnostics) load() {
	// This diagnostic runs once, only after real port exhaustion. It neither
	// changes TCP settings nor delays routing startup or the refused packet.
	config, err := readPortConfiguration(p.ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.state, p.err = "error", portConfigurationError(err)
		if p.ctx.Err() != nil {
			p.state = "cancelled"
			return
		}
		log.Printf("Windows TCP port configuration unavailable: %v", err)
		return
	}
	p.state, p.config = "ready", config
	encoded, _ := json.Marshal(config)
	log.Printf("Windows TCP port configuration: %s", encoded)
}

// portConfigurationError is the worker's failure as stats keep it: the error
// carries the worker's whole output (up to 4 MiB), so 4 KiB of it.
func portConfigurationError(err error) string { return engine.Clip(err.Error(), 4096) }

func (p *portDiagnostics) stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{"exhaustions": p.count.Load(), "configurationStatus": p.state,
		"configuration": append([]portTemplate(nil), p.config...), "configurationError": p.err,
		"reuseUnicastPortRequested": true}
}

func (p *portDiagnostics) close() {
	p.cancel()
	p.wait.Wait()
}
