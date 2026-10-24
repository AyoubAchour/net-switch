package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

type closureIntent struct {
	ID          string              `json:"intentId"`
	Revision    uint64              `json:"revision"`
	PeriodStart float64             `json:"periodStart"`
	Purpose     string              `json:"purpose,omitempty"`
	Label       string              `json:"label,omitempty"`
	Request     engine.CloseRequest `json:"request"`
}

type closureRetry struct {
	attempts int
	nextAt   int64
}

// Journal writes run under applyMu. The compatibility launcher retains its
// milestone-one best-effort behavior. Services commit the complete desired
// state before engine mutations and recover from that authoritative record.
func (c *Core) persistJournal() error {
	return c.writeJournal(nil)
}

// routingIntent is a change to the owner's routing choice. A fresh intent
// also clears the retry backoff and the crash latch.
type routingIntent struct{ wanted, fresh bool }

// commitIntent writes the owner's routing choice before publishing it. The
// supervisor reads wanted and the retry schedule without applyMu, so a choice
// the journal refused must never appear in memory: it would start routing
// once writes recover, after the owner was told the request failed. Callers
// hold applyMu, which orders every journal write.
func (c *Core) commitIntent(next routingIntent) error {
	if err := c.writeJournal(&next); err != nil {
		return err
	}
	c.mu.Lock()
	c.publishIntentLocked(next)
	c.mu.Unlock()
	return nil
}

func (c *Core) publishIntentLocked(next routingIntent) {
	c.wanted = next.wanted
	if next.fresh {
		c.retryAttempts, c.retryAt, c.failureTimes, c.adapterLosses = 0, 0, nil, nil
	}
}

// writeJournal records the current state. A pending intent stands in for the
// published one, so the record matches what commitIntent will publish.
func (c *Core) writeJournal(pending *routingIntent) error {
	if c.op.Journal == nil {
		return nil
	}
	c.mu.Lock()
	number := c.revision
	intents := append([]closureIntent{}, c.closures...)
	desired, instance := c.pendingRevision, c.pendingInstance
	values := map[string]any{}
	for k, v := range c.values {
		values[k] = v
	}
	failures := append([]int64{}, c.failureTimes...)
	losses := append([]int64{}, c.adapterLosses...)
	wanted := c.wanted
	if pending != nil {
		wanted = pending.wanted
		if pending.fresh {
			failures, losses = []int64{}, []int64{}
		}
	}
	failureID := c.lastFailureID
	c.mu.Unlock()
	record := map[string]any{
		"revision": number, "closures": intents,
		"desired": settings.Delete, "settings": settings.Delete,
	}
	if c.op.ServiceMode {
		record["desired"], record["settings"], record["engineInstanceId"], record["failures"] = desired, values, instance, failures
		record["wanted"], record["bootId"] = wanted, c.op.BootID
		record["lastFailureId"] = failureID
		record["adapterLosses"] = losses
	}
	_, err := c.op.Journal.Update(record)
	if err != nil {
		if c.op.ServiceMode {
			return fmt.Errorf("control journal was not committed; engine unchanged: %w", err)
		}
		c.log("CONTROL JOURNAL WRITE FAILED: %v; routing continues, crash recovery is incomplete", err)
	}
	return nil
}

func (c *Core) persistRevision(p engine.Policy, intents []closureIntent) (engine.Revision, error) {
	b, err := js.Marshal(p)
	if err != nil {
		return engine.Revision{}, err
	}
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:])
	snapshot := c.op.Engine.Snapshot()
	c.mu.Lock()
	if previous := c.pendingRevision; previous != nil && c.pendingInstance == snapshot.Instance &&
		snapshot.AppliedRevision < previous.Number && previous.Hash == hash && reflect.DeepEqual(c.closures, intents) {
		c.mu.Unlock()
		if c.op.ServiceMode {
			if err := c.persistJournal(); err != nil {
				return engine.Revision{}, err
			}
		}
		return *previous, nil
	}
	number := c.revision + 1
	if c.op.ServiceMode {
		number = max(c.revision, snapshot.AppliedRevision) + 1
	}
	c.mu.Unlock()
	revision := engine.Revision{Number: number, Hash: hash, Policy: p}
	applied := snapshot.AppliedRevision
	for i := range intents {
		if intents[i].Revision == 0 || (!cutoffKnown(intents[i].Request) && intents[i].Revision > applied) {
			intents[i].Revision = number
			intents[i].Request.BeforeRevision = number
		}
	}
	c.mu.Lock()
	oldNumber, oldPending, oldInstance, oldClosures := c.revision, c.pendingRevision, c.pendingInstance, c.closures
	c.revision = number
	c.pendingRevision, c.pendingInstance = &revision, snapshot.Instance
	c.closures = append([]closureIntent{}, intents...)
	c.mu.Unlock()
	if err := c.persistJournal(); err != nil {
		c.mu.Lock()
		c.revision, c.pendingRevision, c.pendingInstance, c.closures = oldNumber, oldPending, oldInstance, oldClosures
		c.mu.Unlock()
		return engine.Revision{}, err
	}
	c.checkpoint("control-after-desired-commit")
	return revision, nil
}

func readClosures(value any) ([]closureIntent, error) {
	result := []closureIntent{}
	for _, v := range array(value) {
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
func (c *Core) pendingClosures() ([]closureIntent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]closureIntent{}, c.closures...), nil
}
func (c *Core) completeIntent(id string) error {
	c.mu.Lock()
	pending := []closureIntent{}
	for _, intent := range c.closures {
		if intent.ID != id {
			pending = append(pending, intent)
		}
	}
	c.closures = pending
	delete(c.closureRetries, id)
	delete(c.deferClosures, id)
	c.mu.Unlock()
	return c.persistJournal()
}
func (c *Core) saveIntent(intent closureIntent) error {
	c.mu.Lock()
	found := false
	for i := range c.closures {
		if c.closures[i].ID == intent.ID {
			c.closures[i] = intent
			found = true
			break
		}
	}
	if !found {
		c.closures = append(c.closures, intent)
	}
	c.mu.Unlock()
	return c.persistJournal()
}

// cutoffKnown reports whether a line closure has its apply-point cutoff: the
// native engine's point, or the adapter's acknowledgement time.
func cutoffKnown(r engine.CloseRequest) bool {
	return r.StartedBeforePoint != 0 || !r.StartedBefore.IsZero()
}

// recordCutoff stores an acknowledged apply point in the form the engine
// dialect understands. A native acknowledgement always carries its point.
func recordCutoff(r *engine.CloseRequest, ack engine.Acknowledgement) {
	if ack.Point != 0 {
		r.StartedBeforePoint = ack.Point
		return
	}
	r.StartedBefore = ack.AppliedAt
}

func closureNeeded(p engine.Policy, line string) bool {
	if target := p.Lanes[line]; target != "" && target != line {
		return true
	}
	for _, id := range p.Blocked {
		if id == line {
			return true
		}
	}
	return false
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
		if !cutoffKnown(intent.Request) && intent.Revision != 0 {
			if intent.Revision == s.AppliedRevision && (s.AppliedPoint != 0 || !s.AppliedAt.IsZero()) {
				recordCutoff(&intent.Request, engine.Acknowledgement{Point: s.AppliedPoint, AppliedAt: s.AppliedAt})
				if err := c.saveIntent(intent); err != nil {
					return nil, err
				}
			}
			if intent.Revision < s.AppliedRevision {
				return nil, fmt.Errorf("closure %s has an unconfirmed cutoff for revision %d; refusing to broaden it", intent.ID, intent.Revision)
			}
			if intent.Revision > s.AppliedRevision {
				if !closureNeeded(p, intent.Request.Line) {
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
		if !cutoffKnown(intents[i].Request) && intents[i].Request.BeforeRevision == ack.Number {
			recordCutoff(&intents[i].Request, ack)
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
	snapshot := c.op.Engine.Snapshot()
	before := snapshot.Policy
	var err error
	intents, err = c.reconcileIntents(intents, p)
	if err != nil {
		return err
	}
	needsRevision := snapshot.AppliedRevision == 0 || !reflect.DeepEqual(before, p)
	for _, intent := range intents {
		needsRevision = needsRevision || intent.Revision == 0 || intent.Revision > snapshot.AppliedRevision
	}
	if !needsRevision {
		return nil
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
	c.recordLanesLocked(p)
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
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	intents, err := c.pendingClosures()
	if err != nil {
		return err
	}
	s := c.op.Engine.Snapshot()
	var failures []error
	for _, intent := range intents {
		c.mu.Lock()
		deferred := false
		if at, ok := c.deferClosures[intent.ID]; ok {
			deferred = at == c.pollSequence
		}
		stale := gen != c.generation
		waiting := c.now() < c.closureRetries[intent.ID].nextAt
		c.mu.Unlock()
		if stale {
			return nil
		}
		if deferred || waiting {
			continue
		}
		request := intent.Request
		if request.Instance != s.Instance {
			if err := c.completeIntent(intent.ID); err != nil {
				return err
			}
			continue
		}
		if !cutoffKnown(request) && (request.BeforeRevision == 0 || request.BeforeRevision > s.AppliedRevision) {
			continue
		}
		result, err := c.op.Engine.CloseFlows(ctx, request)
		if result.Failed > 0 {
			err = fmt.Errorf("%d connections could not be closed", result.Failed)
		}
		if err != nil {
			failures = append(failures, c.retryClosure(intent, err))
			continue
		}
		c.checkpoint("control-after-close-ack")
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
	return errors.Join(failures...)
}

func (c *Core) retryClosure(intent closureIntent, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	retry := c.closureRetries[intent.ID]
	delays := [...]int64{2000, 5000, 15000, 30000, 60000}
	delay := delays[min(retry.attempts, len(delays)-1)]
	retry.attempts++
	retry.nextAt = c.now() + delay
	c.closureRetries[intent.ID] = retry
	label := c.labelLocked(intent.Request.Line)
	if intent.Purpose == "reconnect" {
		label = "Reconnect " + intent.Label
	}
	return fmt.Errorf("%s: %w; retrying in %d seconds", label, err, delay/1000)
}

// ReplayClosures runs after restoring the desired policy. Old-instance intents
// are discarded: those sockets died with that engine and must never hit new ones.
func (c *Core) ReplayClosures(ctx context.Context) error {
	c.mu.Lock()
	gen := c.generation
	c.mu.Unlock()
	return c.finishClosures(ctx, gen)
}
