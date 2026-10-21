//go:build windows && netswitch_handlecheck

package winhandle

import (
	"encoding/json"
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

const Enabled = true

type event struct {
	Sequence   uint64 `json:"sequence"`
	Value      uint64 `json:"handle"`
	Generation uint64 `json:"generation"`
	Action     string `json:"action"`
	Site       string `json:"site"`
	Error      string `json:"error,omitempty"`
}

type entry struct {
	generation uint64
	state      string
	open, last event
	history    [8]event
	events     uint64
	driver     bool
}

type registry struct {
	mu               sync.Mutex
	sequence         uint64
	opens, uses      uint64
	closes, finished uint64
	values           map[windows.Handle]*entry
}

var handles = registry{values: map[windows.Handle]*entry{}}

func (r *registry) next(o Owner, action, site string) event {
	r.sequence++
	return event{Sequence: r.sequence, Value: uint64(o.value), Generation: o.generation, Action: action, Site: site}
}

func (e *entry) remember(value event) {
	e.history[e.events%uint64(len(e.history))] = value
	e.events++
}

func (r *registry) fail(o Owner, site, reason string, e *entry) {
	var history []event
	if e != nil {
		for i := e.events - min(e.events, uint64(len(e.history))); i < e.events; i++ {
			history = append(history, e.history[i%uint64(len(e.history))])
		}
	}
	state := map[string]any{"reason": reason, "site": site, "handle": uint64(o.value),
		"generation": o.generation, "sequence": r.sequence, "history": history}
	if e != nil {
		state["currentGeneration"], state["state"], state["open"], state["lastUse"] = e.generation, e.state, e.open, e.last
	}
	b, _ := json.Marshal(state)
	panic("WINDOWS HANDLE OWNERSHIP VIOLATION " + string(b))
}

func (r *registry) open(value windows.Handle, site string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value == windows.InvalidHandle {
		r.fail(Owner{value: value}, site, "invalid fresh handle", nil)
	}
	e := r.values[value]
	if e == nil {
		e = &entry{}
		r.values[value] = e
	} else if e.state == "live" {
		if !e.driver {
			r.fail(Owner{value, e.generation}, site, "fresh open collided with a live owner", e)
		}
		e.remember(r.next(Owner{value, e.generation}, "driver-recycled", site))
	}
	e.generation++
	e.state = "live"
	e.driver = false
	e.open = r.next(Owner{value, e.generation}, "open", site)
	e.last = e.open
	e.remember(e.open)
	r.opens++
	return e.generation
}

func (r *registry) use(o Owner, site string, goBorrow bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.values[o.value]
	if e == nil || e.generation != o.generation || (e.state != "live" && !(goBorrow && e.state == "Go closing")) {
		r.fail(o, site, "use of an ended or replaced generation", e)
	}
	e.last = r.next(o, "use", site)
	r.uses++
}

func (r *registry) close(o Owner, site string, goOwner bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.values[o.value]
	if e == nil || e.generation != o.generation || e.state != "live" {
		r.fail(o, site, "second close or stale owner", e)
	}
	e.state = "closed"
	if goOwner {
		e.state = "Go closing"
	}
	e.remember(r.next(o, "close-begin", site))
	r.closes++
}

func (r *registry) finish(o Owner, site string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.values[o.value]
	// Windows can reuse a value after the native close returns but before this
	// goroutine resumes. Record completion against the old generation only.
	if e == nil {
		r.fail(o, site, "close completion has no open record", nil)
	}
	if e.generation == o.generation {
		e.state = "closed"
	}
	done := r.next(o, "close-end", site)
	if err != nil {
		done.Error = fmt.Sprint(err)
	}
	e.remember(done)
	r.finished++
}

func opened(value windows.Handle, site string) uint64 { return handles.open(value, site) }
func used(o Owner, site string, borrow bool)          { handles.use(o, site, borrow) }
func closing(o Owner, site string, goOwner bool)      { handles.close(o, site, goOwner) }
func closed(o Owner, site string, err error)          { handles.finish(o, site, err) }

func driverOwned(o Owner) {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	e := handles.values[o.value]
	if e == nil || e.generation != o.generation || e.state != "live" {
		handles.fail(o, "driver ownership", "invalid driver-owned generation", e)
	}
	e.driver = true
}

func driverReleased(o Owner, site string) {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	e := handles.values[o.value]
	if e == nil {
		handles.fail(o, site, "driver release has no open record", nil)
	}
	if e.generation == o.generation {
		if !e.driver || e.state != "live" {
			handles.fail(o, site, "driver released a non-live driver handle", e)
		}
		e.state = "closed"
	}
	e.remember(handles.next(o, "driver-release-observed", site))
}

func Stats() any {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	live := 0
	for _, e := range handles.values {
		if e.state == "live" {
			live++
		}
	}
	return map[string]any{"enabled": true, "opens": handles.opens, "uses": handles.uses,
		"closes": handles.closes, "finishedCloses": handles.finished, "live": live,
		"values": len(handles.values), "sequence": handles.sequence}
}
