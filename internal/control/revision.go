package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

type closureIntent struct {
	ID       string              `json:"intentId"`
	Revision uint64              `json:"revision"`
	Request  engine.CloseRequest `json:"request"`
}

func (c *Core) persistRevision(p engine.Policy, intents []closureIntent) (engine.Revision, error) {
	b, err := js.Marshal(p)
	if err != nil {
		return engine.Revision{}, err
	}
	sum := sha256.Sum256(b)
	c.mu.Lock()
	number := c.revision + 1
	c.mu.Unlock()
	revision := engine.Revision{Number: number, Hash: hex.EncodeToString(sum[:]), Policy: p}
	if c.op.Journal != nil {
		_, err = c.op.Journal.Change(func(v map[string]any) map[string]any {
			pending := array(v["closures"])
			for _, intent := range intents {
				intent.Revision = number
				pending = append(pending, intent)
			}
			// The journal atomically records the complete desired settings and
			// revision alongside its closure intents. settings.json remains the
			// backwards-compatible mirror consumed by the Node installation.
			return map[string]any{"revision": number, "desired": revision, "settings": c.op.Settings.RawValues(), "closures": pending}
		})
		if err != nil {
			return engine.Revision{}, err
		}
	}
	c.mu.Lock()
	c.revision = number
	c.mu.Unlock()
	return revision, nil
}
func (c *Core) completeIntent(id string) error {
	if c.op.Journal == nil {
		return nil
	}
	_, err := c.op.Journal.Change(func(v map[string]any) map[string]any {
		pending := []any{}
		for _, raw := range array(v["closures"]) {
			if js.Object(raw)["intentId"] != id {
				pending = append(pending, raw)
			}
		}
		return map[string]any{"closures": pending}
	})
	return err
}
func (c *Core) applyWithClosures(ctx context.Context, p engine.Policy, intents []closureIntent, gen uint64) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	r, err := c.persistRevision(p, intents)
	if err != nil {
		return err
	}
	ack, err := c.op.Engine.Apply(ctx, r)
	if err != nil {
		return err
	}
	if ack.Number != r.Number || ack.Hash != r.Hash {
		return fmt.Errorf("engine acknowledged a different revision")
	}
	c.mu.Lock()
	if gen != c.generation {
		c.mu.Unlock()
		return nil
	}
	for id, target := range p.Lanes {
		if l := c.lanes[id]; l != nil {
			l.target = ptr(target)
		}
	}
	c.mu.Unlock()
	for _, intent := range intents {
		request := intent.Request
		if request.Instance != ack.Instance {
			if err := c.completeIntent(intent.ID); err != nil {
				return err
			}
			continue
		}
		if request.StartedBefore.IsZero() {
			request.StartedBefore = ack.AppliedAt
		}
		result, err := c.op.Engine.CloseFlows(ctx, request)
		if err != nil {
			return err
		}
		if result.Failed > 0 {
			return fmt.Errorf("%d connections on %s could not be closed", result.Failed, request.Line)
		}
		if err := c.completeIntent(intent.ID); err != nil {
			return err
		}
		c.mu.Lock()
		if gen == c.generation {
			delete(c.closePending, request.Line)
		}
		c.mu.Unlock()
	}
	return nil
}

// ReplayClosures runs after restoring the desired policy. Old-instance intents
// are discarded: those sockets died with that engine and must never hit new ones.
func (c *Core) ReplayClosures(ctx context.Context) error {
	if c.op.Journal == nil {
		return nil
	}
	s := c.op.Engine.Snapshot()
	for _, v := range array(c.op.Journal.Values()["closures"]) {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var intent closureIntent
		if err := json.Unmarshal(b, &intent); err != nil {
			return err
		}
		if intent.Request.Instance == s.Instance {
			result, err := c.op.Engine.CloseFlows(ctx, intent.Request)
			if err != nil {
				return err
			}
			if result.Failed > 0 {
				return fmt.Errorf("closure intent %s remains incomplete", intent.ID)
			}
		}
		if err := c.completeIntent(intent.ID); err != nil {
			return err
		}
	}
	return nil
}

var _ = time.Time{}
