//go:build linux && acceptance

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

// This file, including every fault implementation, is absent from production.
func (p *Platform) InstallAcceptanceHooks(e *engine.Engine, s *protocol.Server) {
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
