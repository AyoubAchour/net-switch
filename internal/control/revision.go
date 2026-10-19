package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
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
			existing := map[string]bool{}
			for _, raw := range pending {
				existing[js.Text(js.Object(raw)["intentId"])] = true
			}
			for _, intent := range intents {
				if existing[intent.ID] {
					continue
				}
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

func (c *Core) pendingClosures() ([]closureIntent, error) {
	result := []closureIntent{}
	if c.op.Journal == nil {
		return result, nil
	}
	for _, v := range array(c.op.Journal.Values()["closures"]) {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var intent closureIntent
		if err := json.Unmarshal(b, &intent); err != nil {
			return nil, err
		}
		result = append(result, intent)
	}
	return result, nil
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
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock();stale:=gen!=c.generation;c.mu.Unlock();if stale{return nil}
	before := c.op.Engine.Snapshot().Policy
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
	for _, line := range p.Lines {
		id, target := line.ID, p.Lanes[line.ID]
		if l := c.lanes[id]; l != nil {
			if l.target == nil || *l.target != target {
				c.log("%s's apps now use %s", c.labelLocked(id), c.labelLocked(target))
			}
			l.target = ptr(target)
		}
	}
	c.logPolicyRulesLocked(before, p, true)
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
		if result.Closed > 0 {
			plural := ""
			if result.Closed != 1 {
				plural = "s"
			}
			c.mu.Lock()
			label := c.labelLocked(request.Line)
			c.mu.Unlock()
			c.log("%s is out of data: closed %d connection%s still using it", label, result.Closed, plural)
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
