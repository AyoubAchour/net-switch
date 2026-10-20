//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

type portTemplate struct {
	SettingName                     string
	DynamicPortRangeStartPort        *uint32
	DynamicPortRangeNumberOfPorts    *uint32
	AutoReusePortRangeStartPort      *uint32
	AutoReusePortRangeNumberOfPorts  *uint32
}

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
	ctx, cancel := context.WithTimeout(p.ctx, 60*time.Second)
	defer cancel()
	directory, err := windows.GetSystemDirectory()
	var config []portTemplate
	if err == nil {
		command := exec.CommandContext(ctx, filepath.Join(directory, "WindowsPowerShell", "v1.0", "powershell.exe"),
			"-NoProfile", "-NonInteractive", "-Command",
			"Get-NetTCPSetting | Select-Object SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,AutoReusePortRangeStartPort,AutoReusePortRangeNumberOfPorts | ConvertTo-Json -Compress")
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW | windows.IDLE_PRIORITY_CLASS}
		command.WaitDelay = time.Second
		var output []byte
		output, err = command.Output()
		if err == nil {
			err = json.Unmarshal(output, &config)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.state, p.err = "error", err.Error()
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
