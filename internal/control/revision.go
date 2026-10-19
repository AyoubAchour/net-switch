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
	ID          string              `json:"intentId"`
	Revision    uint64              `json:"revision"`
	PeriodStart float64             `json:"periodStart"`
	Purpose     string              `json:"purpose,omitempty"`
	Request     engine.CloseRequest `json:"request"`
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
	applied := c.op.Engine.Snapshot().AppliedRevision
	for i := range intents {
		if intents[i].Revision == 0 || (intents[i].Request.StartedBefore.IsZero() && intents[i].Revision > applied) {
			intents[i].Revision = number
			intents[i].Request.BeforeRevision = number
		}
	}
	if c.op.Journal != nil {
		_, err = c.op.Journal.Change(func(v map[string]any) map[string]any {
			pending := array(v["closures"])
			existing := map[string]int{}
			for i, raw := range pending {
				existing[js.Text(js.Object(raw)["intentId"])] = i
			}
			for _, intent := range intents {
				if index, ok := existing[intent.ID]; ok {
					pending[index] = intent
					continue
				}
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
func (c *Core) saveIntent(intent closureIntent) error {
	if c.op.Journal == nil {
		return nil
	}
	_, err := c.op.Journal.Change(func(v map[string]any) map[string]any {
		pending := array(v["closures"])
		for i, raw := range pending {
			if js.Object(raw)["intentId"] == intent.ID {
				pending[i] = intent
			}
		}
		return map[string]any{"closures": pending}
	})
	return err
}

// Before advancing the revision, recover any acknowledgement whose journal
// update was interrupted. Never replace an earlier confirmed cutoff with now.
func (c *Core) reconcileIntents(intents []closureIntent, p engine.Policy) ([]closureIntent, error) {
	s := c.op.Engine.Snapshot()
	out := []closureIntent{}
	for _, intent := range intents {
		if intent.Request.Instance != s.Instance {
			if err := c.completeIntent(intent.ID); err != nil {
				return nil, err
			}
			continue
		}
		if intent.Request.StartedBefore.IsZero() && intent.Revision != 0 {
			if intent.Revision == s.AppliedRevision && !s.AppliedAt.IsZero() {
				intent.Request.StartedBefore = s.AppliedAt
				if err := c.saveIntent(intent); err != nil {
					return nil, err
				}
			}
			if intent.Revision < s.AppliedRevision {
				return nil, fmt.Errorf("closure %s has an unconfirmed cutoff for revision %d; refusing to broaden it", intent.ID, intent.Revision)
			}
			if intent.Revision > s.AppliedRevision {
				needed := p.Lanes[intent.Request.Line] != "" && p.Lanes[intent.Request.Line] != intent.Request.Line
				for _, id := range p.Blocked {
					needed = needed || id == intent.Request.Line
				}
				if !needed {
					if err := c.completeIntent(intent.ID); err != nil {
						return nil, err
					}
					continue
				}
			}
		}
		out = append(out, intent)
	}
	return out, nil
}
func (c *Core) recordIntentAcks(intents []closureIntent, ack engine.Acknowledgement) error {
	for i := range intents {
		if intents[i].Request.StartedBefore.IsZero() && intents[i].Request.BeforeRevision == ack.Number {
			intents[i].Request.StartedBefore = ack.AppliedAt
			if err := c.saveIntent(intents[i]); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *Core) applyWithClosures(ctx context.Context, p engine.Policy, intents []closureIntent, gen uint64) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	stale := gen != c.generation
	c.mu.Unlock()
	if stale {
		return nil
	}
	before := c.op.Engine.Snapshot().Policy
	var err error
	intents, err = c.reconcileIntents(intents, p)
	if err != nil {
		return err
	}
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
	if err := c.recordIntentAcks(intents, ack); err != nil {
		return err
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
	for _, intent := range intents {
		newBlock, wasBlocked := false, false
		for _, id := range p.Blocked {
			newBlock = newBlock || id == intent.Request.Line
		}
		for _, id := range before.Blocked {
			wasBlocked = wasBlocked || id == intent.Request.Line
		}
		if newBlock && !wasBlocked && p.Lanes[intent.Request.Line] == intent.Request.Line && intent.Revision == r.Number {
			c.deferClosures[intent.ID] = c.pollSequence
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *Core) finishClosures(ctx context.Context, gen uint64) error {
	intents, err := c.pendingClosures()
	if err != nil {
		return err
	}
	s := c.op.Engine.Snapshot()
	for _, intent := range intents {
		c.mu.Lock()
		deferred := false
		if at, ok := c.deferClosures[intent.ID]; ok {
			deferred = at == c.pollSequence
		}
		stale := gen != c.generation
		c.mu.Unlock()
		if stale {
			return nil
		}
		if deferred {
			continue
		}
		request := intent.Request
		if request.Instance != s.Instance {
			if err := c.completeIntent(intent.ID); err != nil {
				return err
			}
			continue
		}
		if request.StartedBefore.IsZero() && (request.BeforeRevision == 0 || request.BeforeRevision > s.AppliedRevision) {
			continue
		}
		result, err := c.op.Engine.CloseFlows(ctx, request)
		if err != nil {
			return err
		}
		if result.Failed > 0 {
			return fmt.Errorf("%d connections on %s could not be closed", result.Failed, request.Line)
		}
		if result.Closed > 0 && intent.Purpose != "reconnect" {
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
		if intent.Purpose == "reconnect" {
			continue
		}
		c.mu.Lock()
		if gen == c.generation {
			delete(c.deferClosures, intent.ID)
			period := float64(0)
			if used := c.usage.Used(request.Line); used != nil {
				period = used.PeriodStart
			}
			if period == intent.PeriodStart {
				delete(c.closePending, request.Line)
			}
		}
		c.mu.Unlock()
	}
	return nil
}

// ReplayClosures runs after restoring the desired policy. Old-instance intents
// are discarded: those sockets died with that engine and must never hit new ones.
func (c *Core) ReplayClosures(ctx context.Context) error {
	c.mu.Lock()
	gen := c.generation
	c.mu.Unlock()
	return c.finishClosures(ctx, gen)
}
