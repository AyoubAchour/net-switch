//go:build linux && acceptance

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

// This file, including every fault implementation, is absent from production.
func (p *Platform) InstallAcceptanceHooks(e *engine.Engine, s *protocol.Server) {
	if path := os.Getenv("NETSWITCH_ACCEPTANCE_PROFILE"); path != "" {
		path = strings.TrimSuffix(path, filepath.Ext(path)) + "-" + p.Instance + ".pprof"
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			panic(err)
		}
		runtime.SetBlockProfileRate(1_000_000)
		p.testClose = func() {
			pprof.StopCPUProfile()
			f.Close()
			runtime.SetBlockProfileRate(0)
			block, err := os.OpenFile(filepath.Join(filepath.Dir(path), "block-"+p.Instance+".pprof"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			}
			if err := pprof.Lookup("block").WriteTo(block, 0); err != nil {
				block.Close()
				panic(err)
			}
			block.Close()
		}
	}
	var gates sync.Mutex
	var lookupGate, writeGate chan struct{}
	var unknown bool
	var pressure []byte
	p.Owners.fault = func(ctx context.Context) error {
		gates.Lock()
		gate, miss := lookupGate, unknown
		gates.Unlock()
		if gate != nil {
			// Intentionally hold beyond the normal lookup deadline to exercise
			// pending queues. Engine shutdown still cancels the injected stall.
			select {
			case <-gate:
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
		}
		if miss {
			return errForcedUnknown
		}
		return nil
	}
	p.WrapTun = func(t platform.TunDevice) platform.TunDevice {
		return &stalledTun{TunDevice: t, gate: func() <-chan struct{} { gates.Lock(); defer gates.Unlock(); return writeGate }}
	}
	var mode atomic.Int32
	var delay atomic.Int64
	var pending sync.WaitGroup
	capacity := make(chan struct{}, 1024)
	p.Owners.destroyFault = func(ctx context.Context, row socketRow, deliver func()) {
		switch mode.Load() {
		case 1:
			return
		case 2:
			select {
			case capacity <- struct{}{}:
			default:
				return
			}
			pending.Go(func() {
				defer func() { <-capacity }()
				timer := time.NewTimer(time.Duration(delay.Load()))
				defer timer.Stop()
				select {
				case <-ctx.Done():
				case <-timer.C:
					deliver()
				}
			})
		default:
			deliver()
		}
	}
	s.TestFault = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var f struct {
			Kind, Mode string
			Delay      time.Duration
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		if f.Kind == "resolver" && f.Mode == "read" {
			data, err := os.ReadFile("/etc/resolv.conf")
			return struct {
				Active      bool
				Description string
			}{false, string(data)}, err
		}
		ack := func() any {
			return struct {
				Active      bool
				Description string
			}{true, f.Kind + ": " + f.Mode}
		}
		if f.Kind == "owner-lookups" || f.Kind == "tun-writer" || f.Kind == "heap-pressure" {
			gates.Lock()
			defer gates.Unlock()
			switch f.Kind {
			case "owner-lookups":
				if lookupGate != nil {
					close(lookupGate)
					lookupGate = nil
				}
				unknown = false
				switch f.Mode {
				case "hold":
					lookupGate = make(chan struct{})
				case "unknown":
					unknown = true
				case "off":
				default:
					return nil, errors.New("invalid lookup fault")
				}
			case "tun-writer":
				if writeGate != nil {
					close(writeGate)
					writeGate = nil
				}
				switch f.Mode {
				case "hold":
					writeGate = make(chan struct{})
				case "off":
				default:
					return nil, errors.New("invalid TUN fault")
				}
			case "heap-pressure":
				switch f.Mode {
				case "on":
					pressure = make([]byte, 512<<20)
					for i := 0; i < len(pressure); i += 4096 {
						pressure[i] = 1
					}
				case "off":
					runtime.KeepAlive(pressure)
					pressure = nil
				case "collect":
					runtime.GC()
					runtime.KeepAlive(pressure)
				default:
					return nil, errors.New("invalid heap fault")
				}
			}
			return ack(), nil
		}
		if f.Kind != "udp-destroy-notifications" {
			return nil, errors.New("unsupported acceptance fault")
		}
		switch f.Mode {
		case "drop":
			mode.Store(1)
		case "delay":
			if f.Delay < 0 || f.Delay > 10*time.Second {
				return nil, errors.New("delay out of range")
			}
			delay.Store(int64(f.Delay))
			mode.Store(2)
		case "off":
			mode.Store(0)
		default:
			return nil, errors.New("invalid notification fault mode")
		}
		return struct {
			Active      bool
			Description string
		}{true, "UDP destroy listener: " + f.Mode + "; one-second reconciliation remains active"}, nil
	}
}

type stalledTun struct {
	platform.TunDevice
	gate func() <-chan struct{}
}

func (t *stalledTun) Stats() any {
	if s, ok := t.TunDevice.(interface{ Stats() any }); ok {
		return s.Stats()
	}
	return nil
}

func (t *stalledTun) WritePacket(ctx context.Context, b []byte) error {
	if gate := t.gate(); gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return t.TunDevice.WritePacket(ctx, b)
}
