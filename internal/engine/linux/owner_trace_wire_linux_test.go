//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/tcp"
)

// wireScan reads a scan snapshot by its documented wire form alone, without
// the package's encoder.
type wireScan struct {
	PID                                      uint32
	Offset                                   int64
	Limit                                    int
	EnqueuedNS, WorkerStartedNS, CompletedNS int64
	Stage, Outcome                           string
	OmittedReads                             int
	ReadsRelativeToEnqueuedNS                [][]int64
}

// wireReads rebuilds a scan's absolute reads: [fd, start, finish] is a
// finished read and [fd, start] a running one, in nanoseconds after EnqueuedNS.
func wireReads(t *testing.T, scan wireScan) []descriptorReadStamp {
	t.Helper()
	reads := make([]descriptorReadStamp, len(scan.ReadsRelativeToEnqueuedNS))
	for i, read := range scan.ReadsRelativeToEnqueuedNS {
		if len(read) != 2 && len(read) != 3 {
			t.Fatalf("scan %d read %d is %v, not [fd, start] or [fd, start, finish]", scan.PID, i, read)
		}
		reads[i] = descriptorReadStamp{FD: read[0], StartedNS: scan.EnqueuedNS + read[1]}
		if len(read) == 3 {
			reads[i].FinishedNS = scan.EnqueuedNS + read[2]
		}
	}
	return reads
}

// legacyRead is how a snapshot used to send each read: a keyed object with
// absolute wall-clock times.
type legacyRead struct{ FD, StartedNS, FinishedNS int64 }

// fullTraceBatch is a scan at its 1024-read bound with the widest values it
// records: 10-digit descriptors, which fs.nr_open allows, 19-digit wall-clock
// nanoseconds, and every read 10 ms or more after enqueue, past the 8 ms batch
// deadline, so each offset has eight digits. Stages come in the scanner's
// order, with a second getdents mid-window.
func fullTraceBatch(pid uint32, queued time.Time, running bool) *descriptorBatch {
	first := int64(1<<30 - 8 - descriptorTraceReads)
	job := &descriptorBatch{key: descriptorBatchKey{pid: pid, offset: first + 2, limit: descriptorTraceReads}, queued: queued, deadline: queued.Add(8 * time.Millisecond)}
	base := queued.UnixNano()
	job.queueAtEnqueue, job.inFlightAtEnqueue = 127, 4
	job.startedNS.Store(base + 7_999_999)
	job.queueAtStart.Store(127)
	job.inFlightAtStart.Store(4)
	job.openedFDPlusOne.Store(1 << 20)
	stages := map[int]int64{0: -3, 1: -4, 2: -5, 3: -2, 4: -1, 517: -1}
	for i := range descriptorTraceReads {
		fd, stage := stages[i]
		if !stage {
			fd = first + int64(i)
		}
		start := base + 10_000_000 + 80_000*int64(i) + int64(pid%1000)
		job.trace.reads = append(job.trace.reads, descriptorReadStamp{FD: fd, StartedNS: start, FinishedNS: start + 40_000 + int64(i)})
	}
	job.trace.omitted = 8
	last := &job.trace.reads[descriptorTraceReads-1]
	if running {
		// A deadline failure is recorded while its worker is still reading.
		job.stage.Store(3)
		last.FinishedNS = 0
	} else {
		job.stage.Store(6)
		job.completedNS.Store(last.FinishedNS + 1)
	}
	return job
}

// loadedEngine is the real engine's Stats plus what only a running stack can
// add: the TCP flow list.
type loadedEngine struct {
	*engine.Engine
	tcpFlows []tcp.Diagnostic
}

func (r loadedEngine) Stats() any {
	s := r.Engine.Stats().(map[string]any)
	s["tcpFlows"], s["tcpFlowsOmitted"] = r.tcpFlows, 0
	return s
}

// widestTCPFlows is engine.Stats' flow list at its 128-flow bound, with every
// field at its widest JSON form, including fields added later.
func widestTCPFlows(t *testing.T) []tcp.Diagnostic {
	t.Helper()
	var flow tcp.Diagnostic
	fields := reflect.ValueOf(&flow).Elem()
	for i := range fields.NumField() {
		switch field := fields.Field(i); {
		case !field.CanSet():
		case field.Kind() == reflect.String:
			field.SetString("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535")
		case field.Kind() == reflect.Bool:
			field.SetBool(false)
		case field.CanInt():
			field.SetInt(math.MinInt64 >> (64 - field.Type().Bits()))
		case field.CanUint():
			field.SetUint(math.MaxUint64 >> (64 - field.Type().Bits()))
		default:
			t.Fatalf("give TCP diagnostic field %s a widest value", fields.Type().Field(i).Name)
		}
	}
	return slices.Repeat([]tcp.Diagnostic{flow}, 128)
}

// statsReply attaches and asks for stats over the control transport, then
// returns the stats reply line exactly as a controller receives it.
func statsReply(t *testing.T, server *protocol.Server) []byte {
	t.Helper()
	controller, transport := net.Pipe()
	if err := controller.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, transport) }()
	defer func() {
		cancel()
		controller.Close()
		<-served
	}()
	replies := bufio.NewReader(controller)
	var line []byte
	for _, request := range []protocol.Request{
		{ID: "attach", Method: "attach", Instance: server.Instance},
		{ID: "stats", Method: "stats", Instance: server.Instance, Epoch: 1},
	} {
		b, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		if line, err = replies.ReadBytes('\n'); err != nil {
			t.Fatal(err)
		}
		var reply struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(line, &reply); err != nil || reply.ID != request.ID || reply.Error != "" {
			t.Fatalf("%s reply %q: error %q, %v", request.Method, reply.ID, reply.Error, err)
		}
	}
	return line
}

// After load the engine can hold eight failed and eight slow scans at their
// read bound while it still lists 128 TCP flows: engine.Stats lists them up to
// that many connections. As keyed objects the reads alone overflowed the 1 MiB
// control reply. The whole reply must now fit with a quarter of it free, and
// carry every read exactly.
func TestFullScanHistoryFitsOneStatsReply(t *testing.T) {
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	address := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")
	row := socketRow{local: netip.AddrPortFrom(address, 65535), remote: netip.AddrPortFrom(address, 65535)}
	queued := time.Now().Add(-time.Second)
	recorded := map[uint32]*descriptorBatch{}
	legacy := 0
	for i := range len(o.batches.failures) + len(o.batches.slow) {
		running := i < len(o.batches.failures)
		job := fullTraceBatch(uint32(4_194_303-i), queued, running)
		recorded[job.key.pid] = job
		if running {
			o.recordBatchWait(ctx, job, row, queued)
		} else {
			o.recordSlowBatch(ctx, job, row, queued)
		}
		old := make([]legacyRead, len(job.trace.reads))
		for j, read := range job.trace.reads {
			old[j] = legacyRead(read)
		}
		b, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		legacy += len(b)
	}
	if legacy <= protocol.MessageLimit {
		t.Fatalf("the reads take %d bytes as keyed objects; the fixture must reproduce the old overflow", legacy)
	}
	// The rest of the owner evidence, at its retained bounds too.
	cause := errors.New(strings.Repeat("x", 600))
	for i := range len(o.udpGenerationFailures) {
		tuple := platform.Tuple{Source: netip.AddrPortFrom(address, uint16(65535-i)), Destination: row.remote}
		base := queued.UnixNano()
		trace := diagQueryTrace{Stage: "receive", ReplyCookie: "ffffffffffffffff", StartedNS: base, SocketReadyNS: base, SentNS: base, ReadStartedNS: base, CompletedNS: base, DeadlineNS: base, Sequence: math.MaxUint32, ReplyReady: true, ReplyFromKernel: true, PeekError: "resource temporarily unavailable"}
		o.recordUDPGenerationFailure(ctx, tuple, "dual-stack-dump", queued, &diagQueryError{Trace: trace, cause: cause})
	}
	o.recordError(cause)
	var timing lookupTiming
	for phase := range timing.phases {
		timing.phases[phase] = 8 * time.Millisecond
	}
	o.recordHolderTimeout(timing, time.Second)

	e := engine.New(ctx, engine.Dependencies{Owners: o}, flows.Defaults(), nil)
	line := statsReply(t, protocol.New(loadedEngine{Engine: e, tcpFlows: widestTCPFlows(t)}, e.Table, nil))
	var reply struct {
		Result struct {
			Engine struct {
				OwnerLookup struct {
					FailedScans, SlowScans []wireScan
					UDPGenerationFailures  []json.RawMessage
				} `json:"ownerLookup"`
				TCPFlows json.RawMessage `json:"tcpFlows"`
			} `json:"engine"`
		} `json:"result"`
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		t.Fatal(err)
	}
	lookup := reply.Result.Engine.OwnerLookup
	var tcpFlows []tcp.Diagnostic
	if err := json.Unmarshal(reply.Result.Engine.TCPFlows, &tcpFlows); err != nil || len(tcpFlows) != 128 || len(lookup.UDPGenerationFailures) != len(o.udpGenerationFailures) {
		t.Fatalf("reply lost other evidence: %d TCP flows, %d UDP generation failures, %v", len(tcpFlows), len(lookup.UDPGenerationFailures), err)
	}
	if len(lookup.FailedScans) != len(o.batches.failures) || len(lookup.SlowScans) != len(o.batches.slow) {
		t.Fatalf("reply has %d failed and %d slow scans", len(lookup.FailedScans), len(lookup.SlowScans))
	}
	compact, running := 0, 0
	for _, scan := range append(lookup.FailedScans, lookup.SlowScans...) {
		job := recorded[scan.PID]
		if job == nil {
			t.Fatalf("scan %d was sent twice or never recorded", scan.PID)
		}
		delete(recorded, scan.PID)
		b, err := json.Marshal(scan.ReadsRelativeToEnqueuedNS)
		if err != nil {
			t.Fatal(err)
		}
		compact += len(b)
		for _, read := range scan.ReadsRelativeToEnqueuedNS {
			if len(read) == 2 {
				running++
			}
		}
		reads := wireReads(t, scan)
		if !slices.Equal(reads, job.trace.reads) {
			i := 0
			for i < min(len(reads), len(job.trace.reads)) && reads[i] == job.trace.reads[i] {
				i++
			}
			t.Fatalf("scan %d sent %d reads for %d recorded; first difference at %d: %+v for %+v", scan.PID, len(reads), len(job.trace.reads), i, reads[i:min(i+1, len(reads))], job.trace.reads[i:min(i+1, len(job.trace.reads))])
		}
		outcome := "slow batch"
		if job.completedNS.Load() == 0 {
			outcome = "deadline"
		}
		scan.ReadsRelativeToEnqueuedNS = nil // checked above; keeps a failure message short
		if scan.EnqueuedNS != job.queued.UnixNano() || scan.WorkerStartedNS != job.startedNS.Load() || scan.CompletedNS != job.completedNS.Load() || scan.Offset != job.key.offset ||
			scan.Limit != job.key.limit || scan.Stage != descriptorStage(job.stage.Load()) || scan.Outcome != outcome || scan.OmittedReads != job.trace.omitted {
			t.Fatalf("scan %d metadata changed on the wire: %+v", scan.PID, scan)
		}
	}
	if len(recorded) != 0 || running != len(o.batches.failures) {
		t.Fatalf("%d recorded scans missing; %d running reads sent, want one per failed scan", len(recorded), running)
	}
	budget := protocol.MessageLimit * 3 / 4
	t.Logf("scan reads: %d bytes as keyed objects, %d as offset arrays; stats reply %d bytes, %d of them TCP flows; limit %d, budget %d",
		legacy, compact, len(line), len(reply.Result.Engine.TCPFlows), protocol.MessageLimit, budget)
	if len(line) > budget {
		t.Fatalf("a full scan history with 128 TCP flows takes %d bytes of the %d-byte reply limit; keep a quarter of it free", len(line), protocol.MessageLimit)
	}
}
