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
	Base     platform.System
	mu       sync.Mutex
	sessions map[string]*desktopEndpoint
	next     int
}
type desktopEndpoint struct {
	pid     uint32
	queue   []DesktopWork
	pending map[string]chan desktopResult
}

func (d *DesktopBridge) Connect(id string, pid uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = map[string]*desktopEndpoint{}
	}
	if d.sessions[id] == nil {
		d.sessions[id] = &desktopEndpoint{pid: pid, pending: map[string]chan desktopResult{}}
	}
}
func (d *DesktopBridge) Disconnect(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	session := d.sessions[id]
	if session == nil {
		return
	}
	delete(d.sessions, id)
	for _, ch := range session.pending {
		ch <- desktopResult{err: errors.New("desktop disconnected")}
	}
}
func (d *DesktopBridge) PID() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, session := range d.sessions {
		return session.pid
	}
	return 0
}
func (d *DesktopBridge) Poll(id string) []DesktopWork {
	d.mu.Lock()
	defer d.mu.Unlock()
	session := d.sessions[id]
	if session == nil {
		return nil
	}
	batch := session.queue
	session.queue = nil
	return batch
}
func (d *DesktopBridge) Complete(id, key string, value any, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	session := d.sessions[id]
	if session == nil {
		return
	}
	if ch := session.pending[key]; ch != nil {
		result := desktopResult{value: value}
		if message != "" {
			result.err = errors.New(message)
		}
		ch <- result
		delete(session.pending, key)
	}
}
func (d *DesktopBridge) Call(ctx context.Context, op string, args map[string]any) (any, error) {
	switch op {
	case "app-info", "installed-apps", "autostart", "autostart-set", "autostart-upgrade":
		d.mu.Lock()
		var session *desktopEndpoint
		for _, candidate := range d.sessions {
			if session == nil || len(candidate.pending) < len(session.pending) {
				session = candidate
			}
		}
		if session == nil {
			d.mu.Unlock()
			return nil, errors.New("owner desktop is not connected")
		}
		if len(session.pending) >= 32 {
			d.mu.Unlock()
			return nil, errors.New("desktop work queue is full")
		}
		work := DesktopWork{ID: randomID(), Operation: op, Args: args}
		ch := make(chan desktopResult, 1)
		session.pending[work.ID] = ch
		session.queue = append(session.queue, work)
		d.mu.Unlock()
		defer func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			delete(session.pending, work.ID)
			for i, queued := range session.queue {
				if queued.ID == work.ID {
					session.queue = append(session.queue[:i], session.queue[i+1:]...)
					break
				}
			}
		}()
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
