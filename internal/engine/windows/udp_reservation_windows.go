//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hosted diagnosis only. After the first automatic UDP allocation refusal,
// one background read compares each family's UDP dynamic port range and its
// active excluded port ranges with the native UDP table captured at the
// refusal. netsh is only asked to show settings; nothing is ever changed and
// the refused flow never waits for these commands.
//
// The timeouts bound evidence collection only. A cold netsh start on a busy
// hosted runner took over 5 s twice (runs 39576436110 and 39587194026), which
// lost the evidence; 15 s per command and 60 s in total keep it.
const (
	reservationCommandTimeout = 15 * time.Second
	reservationProbeTimeout   = 60 * time.Second
	reservationOutputLimit    = 64 << 10
)

type portRange struct {
	Start        int  `json:"start"`
	End          int  `json:"end"`
	Administered bool `json:"administered,omitempty"`
}

type reservationCommandResult struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
	Millis    int64  `json:"millis"`
}

type reservationCommand func(ctx context.Context, args ...string) reservationCommandResult

// Counts are pointers: a value that could not be derived stays absent rather
// than reading as zero. Every count is of distinct port numbers.
type udpFamilyReservation struct {
	Family          string                   `json:"family"`
	DynamicCommand  reservationCommandResult `json:"dynamicPortCommand"`
	ExcludedCommand reservationCommandResult `json:"excludedPortCommand"`
	DynamicRange    *portRange               `json:"dynamicRange,omitempty"`
	ExcludedRanges  []portRange              `json:"excludedRanges,omitempty"`
	ParseErrors     []string                 `json:"parseErrors,omitempty"`
	InUseError      string                   `json:"inUseError,omitempty"`
	InUsePorts      *int                     `json:"inUsePorts,omitempty"`
	DynamicPorts    *int                     `json:"dynamicPorts,omitempty"`
	// Excluded and in-use ports inside the dynamic range, and their overlap.
	ExcludedInDynamic      *int `json:"excludedInDynamic,omitempty"`
	InUseInDynamic         *int `json:"inUseInDynamic,omitempty"`
	InUseExcludedInDynamic *int `json:"inUseAndExcludedInDynamic,omitempty"`
	// Dynamic ports neither excluded nor in use at the refusal. This is table
	// evidence, not a promise: Windows may hold ports no table shows.
	Available *int `json:"available,omitempty"`
}

// started is when the native UDP table was captured.
type udpReservationProbe struct {
	mu       sync.Mutex
	state    string
	reason   string
	started  time.Time
	finished time.Time
	families []udpFamilyReservation
}

func newUDPReservationProbe() *udpReservationProbe {
	return &udpReservationProbe{state: "pending", started: time.Now()}
}

func (p *udpReservationProbe) finish(state, reason string, families []udpFamilyReservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state, p.reason, p.finished, p.families = state, reason, time.Now(), families
}

func (p *udpReservationProbe) MarshalJSON() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value := struct {
		State    string                 `json:"state"`
		Reason   string                 `json:"reason,omitempty"`
		Started  time.Time              `json:"started"`
		Finished *time.Time             `json:"finished,omitempty"`
		Families []udpFamilyReservation `json:"families,omitempty"`
	}{State: p.state, Reason: p.reason, Started: p.started, Families: p.families}
	if !p.finished.IsZero() {
		value.Finished = &p.finished
	}
	return json.Marshal(value)
}

// udpPortSpace is the reusable port-space diagnosis for any first UDP
// allocation failure: the native table is taken when it is captured, and the
// port settings are compared with that table by collect.
type udpPortSpace struct {
	Native   map[string]any       `json:"nativeUDPState"`
	Probe    *udpReservationProbe `json:"udpPortReservation"`
	ports    [2][]uint16
	portsErr error
}

func captureUDPPortSpace() *udpPortSpace {
	native, ports, err := nativeUDPSnapshot()
	return &udpPortSpace{Native: native, Probe: newUDPReservationProbe(), ports: ports, portsErr: err}
}

func (s *udpPortSpace) collect(ctx context.Context, run reservationCommand) {
	families := readUDPReservations(ctx, run, s.ports, s.portsErr)
	state, reason := "complete", ""
	if err := ctx.Err(); err != nil {
		// Commands finished before the interruption keep their results;
		// interrupted ones carry their own error and no derived counts.
		state, reason = "interrupted", err.Error()
	}
	s.Probe.finish(state, reason, families)
}

// diagnoseUDPPortSpace captures and reads synchronously, bounded by the probe
// timeout. It is for hosted fixtures that hold their sockets at the failure
// and can wait; the engine uses reservationJobs instead.
func diagnoseUDPPortSpace(ctx context.Context) *udpPortSpace {
	space := captureUDPPortSpace()
	ctx, cancel := context.WithTimeout(ctx, reservationProbeTimeout)
	defer cancel()
	space.collect(ctx, runNetsh)
	return space
}

// reservationJobs lets Dialer.Close stop and join the single probe. Its zero
// value is ready to use.
type reservationJobs struct {
	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc
	wait   sync.WaitGroup
}

func (j *reservationJobs) start(space *udpPortSpace, run reservationCommand) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		space.Probe.finish("cancelled", "dialer closed before the probe started", nil)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), reservationProbeTimeout)
	j.cancel = cancel
	j.wait.Add(1)
	go func() {
		defer j.wait.Done()
		defer cancel()
		space.collect(ctx, run)
		value, _ := json.Marshal(space.Probe)
		log.Printf("WINDOWS UDP PORT RESERVATION %s", value)
	}()
}

func (j *reservationJobs) close() {
	j.mu.Lock()
	j.closed = true
	if j.cancel != nil {
		j.cancel()
	}
	j.mu.Unlock()
	j.wait.Wait()
}

func readUDPReservations(ctx context.Context, run reservationCommand, inUse [2][]uint16, inUseErr error) []udpFamilyReservation {
	families := make([]udpFamilyReservation, 0, 2)
	for index, family := range []string{"ipv4", "ipv6"} {
		r := udpFamilyReservation{Family: family}
		r.DynamicCommand = run(ctx, "interface", family, "show", "dynamicport", "udp")
		// The active store is the set the stack enforces now, including
		// exclusions made at runtime that are not persisted.
		r.ExcludedCommand = run(ctx, "interface", family, "show", "excludedportrange", "protocol=udp", "store=active")
		if inUseErr != nil {
			r.InUseError = inUseErr.Error()
		}
		r.account(inUse[index], inUseErr == nil)
		families = append(families, r)
	}
	return families
}

func (r *udpFamilyReservation) account(inUse []uint16, haveInUse bool) {
	var excluded []portRange
	excludedOK := false
	if output, ok := r.parseable("dynamic", r.DynamicCommand); ok {
		if value, err := parseDynamicPortRange(output); err != nil {
			r.ParseErrors = append(r.ParseErrors, "dynamic: "+err.Error())
		} else {
			r.DynamicRange = &value
		}
	}
	if output, ok := r.parseable("excluded", r.ExcludedCommand); ok {
		var err error
		if excluded, err = parseExcludedPortRanges(output); err != nil {
			r.ParseErrors = append(r.ParseErrors, "excluded: "+err.Error())
		} else {
			r.ExcludedRanges, excludedOK = excluded, true
		}
	}
	if haveInUse {
		r.InUsePorts = countOf(len(inUse))
	}
	if r.DynamicRange == nil {
		return
	}
	r.DynamicPorts = countOf(r.DynamicRange.End - r.DynamicRange.Start + 1)
	var excludedSet, usedSet portSet
	for _, value := range excluded {
		for port := value.Start; port <= value.End; port++ {
			excludedSet.add(port)
		}
	}
	for _, port := range inUse {
		usedSet.add(int(port))
	}
	var excludedIn, usedIn, both, available int
	for port := r.DynamicRange.Start; port <= r.DynamicRange.End; port++ {
		isExcluded, isUsed := excludedSet.has(port), usedSet.has(port)
		switch {
		case isExcluded && isUsed:
			both++
			excludedIn++
			usedIn++
		case isExcluded:
			excludedIn++
		case isUsed:
			usedIn++
		default:
			available++
		}
	}
	if excludedOK {
		r.ExcludedInDynamic = countOf(excludedIn)
	}
	if haveInUse {
		r.InUseInDynamic = countOf(usedIn)
	}
	if excludedOK && haveInUse {
		r.InUseExcludedInDynamic, r.Available = countOf(both), countOf(available)
	}
}

func (r *udpFamilyReservation) parseable(name string, result reservationCommandResult) (string, bool) {
	switch {
	case result.Error != "":
		return "", false
	case result.Truncated:
		r.ParseErrors = append(r.ParseErrors, name+": output truncated")
		return "", false
	}
	return result.Output, true
}

func countOf(value int) *int { return &value }

type portSet [1024]uint64

func (s *portSet) add(port int)      { s[port>>6] |= 1 << (port & 63) }
func (s *portSet) has(port int) bool { return s[port>>6]&(1<<(port&63)) != 0 }

// netsh prints two "label : number" lines, start port then number of ports.
// Only the numbers are read, so translated labels still parse.
func parseDynamicPortRange(output string) (portRange, error) {
	var values []int
	for _, line := range strings.Split(output, "\n") {
		_, text, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if value, err := strconv.Atoi(strings.TrimSpace(text)); err == nil {
			values = append(values, value)
		}
	}
	if len(values) != 2 {
		return portRange{}, fmt.Errorf("expected start port and number of ports, found %d numeric values", len(values))
	}
	start, count := values[0], values[1]
	if start < 1 || count < 1 || start+count-1 > 65535 {
		return portRange{}, fmt.Errorf("invalid range start=%d count=%d", start, count)
	}
	return portRange{Start: start, End: start + count - 1}, nil
}

// The table has a dashed header rule, then "start end" rows; a trailing "*"
// marks an administered exclusion. Without the rule the output is not
// trusted, so an unrecognized table never reads as "no exclusions".
func parseExcludedPortRanges(output string) ([]portRange, error) {
	ruled := false
	ranges := []portRange{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.Trim(fields[0], "-") == "" {
			ruled = true
			continue
		}
		if !ruled || len(fields) > 3 {
			continue
		}
		start, startErr := strconv.Atoi(fields[0])
		if startErr != nil || len(fields) < 2 {
			continue
		}
		end, endErr := strconv.Atoi(fields[1])
		if endErr != nil {
			return nil, fmt.Errorf("unexpected row %q", strings.TrimSpace(line))
		}
		value := portRange{Start: start, End: end}
		if len(fields) == 3 {
			if fields[2] != "*" {
				return nil, fmt.Errorf("unexpected row %q", strings.TrimSpace(line))
			}
			value.Administered = true
		}
		if start < 1 || end < start || end > 65535 {
			return nil, fmt.Errorf("invalid range %d-%d", start, end)
		}
		ranges = append(ranges, value)
	}
	if !ruled {
		return nil, errors.New("excluded port table header was not found")
	}
	return ranges, nil
}

type boundedOutput struct {
	data      []byte
	truncated bool
}

// Write reports every byte as consumed so the child never blocks on a full
// pipe; bytes beyond the limit are dropped and marked as truncated.
func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if room := reservationOutputLimit - len(b.data); n > room {
		b.truncated = true
		p = p[:max(room, 0)]
	}
	b.data = append(b.data, p...)
	return n, nil
}
