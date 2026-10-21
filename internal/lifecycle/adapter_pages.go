package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

const adapterSnapshotBytes = 16 << 20
const adapterPageBytes = protocol.MessageLimit - 4096

type connectionPage struct {
	Connections []ce.Connection `json:"connections"`
	Cursor      string          `json:"cursor,omitempty"`
}
type adapterSnapshot struct {
	connections []ce.Connection
	sizes       []int
	bytes       int
	expires     time.Time
}
type adapterPages struct {
	mu        sync.Mutex
	snapshots map[string]*adapterSnapshot
	bytes     int
	now       func() time.Time
}

func (p *adapterPages) read(ctx context.Context, cursor string, list func(context.Context) ([]ce.Connection, error)) (connectionPage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.now != nil {
		now = p.now()
	}
	if p.snapshots == nil {
		p.snapshots = map[string]*adapterSnapshot{}
	}
	for id, snapshot := range p.snapshots {
		if !now.Before(snapshot.expires) {
			p.bytes -= snapshot.bytes
			delete(p.snapshots, id)
		}
	}
	id, offset := "", 0
	var snapshot *adapterSnapshot
	if cursor == "" {
		if len(p.snapshots) >= 4 {
			return connectionPage{}, errors.New("flow snapshot limit reached")
		}
		connections, err := list(ctx)
		if err != nil {
			return connectionPage{}, err
		}
		if len(connections) > 65536 {
			return connectionPage{}, errors.New("flow snapshot exceeds 65536 entries")
		}
		snapshot = &adapterSnapshot{connections: connections, sizes: make([]int, len(connections)), expires: now.Add(10 * time.Second)}
		for i, connection := range connections {
			b, err := json.Marshal(connection)
			if err != nil {
				return connectionPage{}, err
			}
			size := len(b) + 1
			if size > adapterPageBytes {
				return connectionPage{}, errors.New("flow record exceeds the IPC page limit")
			}
			snapshot.sizes[i] = size
			snapshot.bytes += size
		}
		if snapshot.bytes+p.bytes > adapterSnapshotBytes {
			return connectionPage{}, errors.New("flow snapshot byte budget reached")
		}
		id = randomID()
		p.snapshots[id] = snapshot
		p.bytes += snapshot.bytes
	} else {
		name, index, ok := strings.Cut(cursor, ":")
		n, err := strconv.ParseUint(index, 10, 32)
		if !ok || err != nil || len(name) != 64 {
			return connectionPage{}, errors.New("invalid flow cursor")
		}
		id, offset = name, int(n)
		snapshot = p.snapshots[id]
		if snapshot == nil || offset >= len(snapshot.connections) {
			return connectionPage{}, errors.New("flow snapshot expired or cursor is invalid")
		}
	}
	end, size := offset, 0
	for end < len(snapshot.connections) && size+snapshot.sizes[end] <= adapterPageBytes {
		size += snapshot.sizes[end]
		end++
	}
	page := connectionPage{Connections: append([]ce.Connection{}, snapshot.connections[offset:end]...)}
	if end < len(snapshot.connections) {
		page.Cursor = id + ":" + strconv.Itoa(end)
	} else {
		p.bytes -= snapshot.bytes
		delete(p.snapshots, id)
	}
	return page, nil
}
