package lifecycle

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform"
)

type DesktopWork struct {
	ID        string         `json:"id"`
	Operation string         `json:"operation"`
	Args      map[string]any `json:"args"`
}
type desktopResult struct {
	value any
	err   error
}
type DesktopBridge struct {
	Base    platform.System
	mu      sync.Mutex
	owner   string
	pid     uint32
	queue   []DesktopWork
	pending map[string]chan desktopResult
}

func (d *DesktopBridge) Connect(id string, pid uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.owner != id {
		for key, ch := range d.pending {
			ch <- desktopResult{err: errors.New("desktop session replaced")}
			delete(d.pending, key)
		}
		d.queue = nil
	}
	d.owner = id
	d.pid = pid
	if d.pending == nil {
		d.pending = map[string]chan desktopResult{}
	}
}
func (d *DesktopBridge) Disconnect(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id != d.owner {
		return
	}
	d.owner = ""
	d.pid = 0
	for key, ch := range d.pending {
		ch <- desktopResult{err: errors.New("desktop disconnected")}
		delete(d.pending, key)
	}
	d.queue = nil
}
func (d *DesktopBridge) PID() uint32 { d.mu.Lock(); defer d.mu.Unlock(); return d.pid }
func (d *DesktopBridge) Poll(id string) []DesktopWork {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id != d.owner {
		return nil
	}
	batch := d.queue
	d.queue = nil
	return batch
}
func (d *DesktopBridge) Complete(id, key string, value any, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id != d.owner {
		return
	}
	if ch := d.pending[key]; ch != nil {
		result := desktopResult{value: value}
		if message != "" {
			result.err = errors.New(message)
		}
		ch <- result
		delete(d.pending, key)
	}
}
func (d *DesktopBridge) Call(ctx context.Context, op string, args map[string]any) (any, error) {
	switch op {
	case "app-info", "installed-apps", "autostart", "autostart-set", "autostart-upgrade":
		d.mu.Lock()
		if d.owner == "" {
			d.mu.Unlock()
			return nil, errors.New("owner desktop is not connected")
		}
		if len(d.pending) >= 32 {
			d.mu.Unlock()
			return nil, errors.New("desktop work queue is full")
		}
		work := DesktopWork{ID: randomID(), Operation: op, Args: args}
		ch := make(chan desktopResult, 1)
		d.pending[work.ID] = ch
		d.queue = append(d.queue, work)
		d.mu.Unlock()
		defer func() { d.mu.Lock(); delete(d.pending, work.ID); d.mu.Unlock() }()
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case result := <-ch:
			return result.value, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, errors.New("desktop work timed out")
		}
	default:
		return d.Base.Call(ctx, op, args)
	}
}
func (d *DesktopBridge) Stream(ctx context.Context, mode string, emit func([]byte), report func(error)) {
	d.Base.Stream(ctx, mode, emit, report)
}
