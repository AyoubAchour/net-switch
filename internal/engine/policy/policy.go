// Package policy compiles immutable routing snapshots. Selection uses integer
// thresholds; neither source-port patterns nor prediction affect the sequence.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

const Fibonacci uint64 = 0x9E3779B97F4A7C15

var ErrBlocked = errors.New("app is pinned to a blocked line")
var ErrIPv6 = errors.New("IPv6 is disabled")

type Config struct {
	Lines    []platform.Line   `json:"lines"`
	AppLines map[string]string `json:"appLines"`
	Combine  bool              `json:"combine"`
	Shares   map[string]uint64 `json:"shares"`
	Lanes    map[string]string `json:"lanes"`
	Blocked  []string          `json:"blocked"`
	IPv6     bool              `json:"ipv6"`
}
type Revision struct {
	N      uint64 `json:"n"`
	Hash   string `json:"hash"`
	Config Config `json:"config"`
}
type Applied struct {
	N     uint64 `json:"n"`
	Hash  string `json:"hash"`
	Point uint64 `json:"point"`
}
type slice struct {
	lane, line string
	end        uint64
	last       bool
	weight     uint64
}
type Policy struct {
	config   Config
	revision uint64
	blocked  map[string]bool
	slices   []slice
	total    uint64
}
type Prediction struct {
	Line         string             `json:"line,omitempty"`
	Distribution map[string]float64 `json:"distribution,omitempty"`
	Blocked      bool               `json:"blocked,omitempty"`
}

func Hash(c Config) string {
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Compile(r Revision) (*Policy, error) {
	if r.N == 0 || r.Hash != Hash(r.Config) {
		return nil, errors.New("invalid revision number or hash")
	}
	b, _ := json.Marshal(r.Config)
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if len(c.Lines) == 0 || len(c.Lines) > 255 {
		return nil, errors.New("need 1 to 255 lines")
	}
	ids := map[string]bool{}
	for _, l := range c.Lines {
		if l.ID == "" || len(l.ID) > 64 || ids[l.ID] {
			return nil, errors.New("invalid or duplicate line")
		}
		ids[l.ID] = true
	}
	p := &Policy{config: c, revision: r.N, blocked: map[string]bool{}}
	for _, id := range c.Blocked {
		if !ids[id] || id == c.Lines[0].ID {
			return nil, errors.New("invalid blocked line")
		}
		p.blocked[id] = true
	}
	if c.Lanes == nil {
		c.Lanes = map[string]string{}
		p.config.Lanes = c.Lanes
	}
	for _, l := range c.Lines {
		if c.Lanes[l.ID] == "" {
			c.Lanes[l.ID] = l.ID
		}
		if !ids[c.Lanes[l.ID]] {
			return nil, errors.New("unknown lane target")
		}
	}
	for id, target := range c.Lanes {
		if !ids[id] || !ids[target] {
			return nil, errors.New("unknown lane")
		}
	}
	for app, id := range c.AppLines {
		if app == "" || len(app) > 512 || !ids[id] {
			return nil, errors.New("invalid app pin")
		}
	}
	for id, w := range c.Shares {
		if !ids[id] || p.blocked[id] {
			return nil, errors.New("invalid sharing line")
		}
		total, carry := bits.Add64(p.total, w, 0)
		if carry != 0 {
			return nil, errors.New("share total overflows")
		}
		p.total = total
	}
	var cumulative uint64
	for _, l := range c.Lines {
		w := c.Shares[l.ID]
		if w == 0 {
			continue
		}
		cumulative += w
		s := slice{lane: l.ID, line: c.Lanes[l.ID], last: cumulative == p.total, weight: w}
		if !s.last {
			s.end, _ = bits.Div64(cumulative, 0, p.total)
		}
		p.slices = append(p.slices, s)
	}
	return p, nil
}

func (p *Policy) Decide(owner platform.Owner, sourcePort uint16, ipv6 bool, k uint64) (flowapi.Decision, error) {
	if ipv6 && !p.config.IPv6 {
		return flowapi.Decision{}, ErrIPv6
	}
	lane := p.config.AppLines[owner.AppID]
	if lane != "" && p.blocked[lane] {
		return flowapi.Decision{}, ErrBlocked
	}
	if lane == "" {
		lane = p.config.Lines[0].ID
		if p.config.Combine && sourcePort >= 1024 && p.total != 0 {
			position := k * Fibonacci
			for _, s := range p.slices {
				if s.last || position < s.end {
					lane = s.lane
					break
				}
			}
		}
	}
	line, ok := p.config.Lanes[lane]
	if !ok {
		return flowapi.Decision{}, fmt.Errorf("no target for lane %s", lane)
	}
	return flowapi.Decision{Lane: lane, Line: line, Revision: p.revision}, nil
}

func (p *Policy) Predict(app string) Prediction {
	if lane := p.config.AppLines[app]; lane != "" {
		return Prediction{Line: p.config.Lanes[lane], Blocked: p.blocked[lane]}
	}
	if p.config.Combine && p.total != 0 {
		d := map[string]float64{}
		for _, s := range p.slices {
			d[s.line] += float64(s.weight) / float64(p.total)
		}
		return Prediction{Distribution: d}
	}
	return Prediction{Line: p.config.Lanes[p.config.Lines[0].ID]}
}
func (p *Policy) IPv6() bool { return p.config.IPv6 }
