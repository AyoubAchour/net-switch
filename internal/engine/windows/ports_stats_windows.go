//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	winplatform "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/platform/worker"
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
	return &portDiagnostics{ctx: ctx, cancel: cancel, state: "notRequested"}
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
	executable, err := os.Executable()
	var config []portTemplate
	if err == nil {
		var value any
		value, err = (worker.Supervisor{Executable: executable}).Once(p.ctx, "tcp-port-configuration", nil)
		if err == nil {
			var output []byte
			output, err = json.Marshal(value)
			if err == nil {
				err = json.Unmarshal(output, &config)
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.state, p.err = "error", err.Error()
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
