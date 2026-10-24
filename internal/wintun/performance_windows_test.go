//go:build windows

package wintun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

func tcpEcho(t *testing.T, f *fixture) func() {
	t.Helper()
	session := f.io
	if os.Getenv("NETSWITCH_WINTUN_INTEGRITY") == "1" {
		if !integrityHooksEnabled {
			t.Fatal("integrity diagnostic requires -tags=wintun_integrity")
		}
		f.integrity = newIntegrityDiagnostic()
		f.integrity.boundary = os.Getenv("NETSWITCH_WINTUN_INTEGRITY_BOUNDARY")
		if f.integrity.boundary == "" {
			f.integrity.boundary = "receive"
		}
		switch f.integrity.boundary {
		case "receive", "ingress", "echo", "output", "send", "host", "all":
		default:
			t.Fatal("unknown integrity boundary")
		}
		f.integrity.emit = func(c *integrityConnection, stage string, failure integrityFailure) {
			reportIntegrityFailure(t, c, stage, failure)
		}
		if s, ok := session.(*dllSession); ok {
			s.integrity = f.integrity
		}
	}
	link := ns.NewLink()
	stack, err := ns.New(link, ns.DefaultOptions())
	must(t, err)
	address := tcpip.AddrFrom4([4]byte{198, 19, 240, 2})
	if e := stack.AddProtocolAddress(ns.NIC, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: address, PrefixLen: 30}}, gv.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	listener, err := gonet.ListenTCP(stack, tcpip.FullAddress{NIC: ns.NIC, Addr: address, Port: 9002}, ipv4.ProtocolNumber)
	must(t, err)
	detach := func() {}
	if os.Getenv("NETSWITCH_WINTUN_BOUNDARIES") == "1" {
		if f.integrity != nil {
			t.Fatal("old and word boundary diagnostics cannot run together")
		}
		f.wordBoundaries, detach = attachWordBoundaries(t, f)
	}
	if f.integrity != nil {
		detach = attachIntegrityRings(t, f.integrity)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var pumps, clients sync.WaitGroup
	pumps.Add(3)
	go func() {
		defer pumps.Done()
		bufs := make([][]byte, 64)
		sizes := make([]int, 64)
		for i := range bufs {
			bufs[i] = make([]byte, MaxPacketSize)
		}
		for {
			n, err := session.ReadBatch(ctx, bufs, sizes)
			if err != nil {
				if ctx.Err() == nil {
					f.recordFault(err)
				}
				return
			}
			for i := 0; i < n; i++ {
				p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(bufs[i][:sizes[i]]))})
				if integrityHooksEnabled && f.integrity != nil && f.integrity.selected("stack_ingress") {
					// MakeWithData creates one owned contiguous view here. Borrow
					// it synchronously instead of cloning the whole packet again.
					views, skip := p.AsViewList()
					first := views.Front()
					if first != nil && first.Next() == nil && skip <= len(first.AsSlice()) {
						f.integrity.packet("stack_ingress", first.AsSlice()[skip:])
					} else {
						v := p.ToView()
						f.integrity.packet("stack_ingress", v.AsSlice())
						v.Release()
					}
				}
				if s, ok := session.(*Session); ok {
					p.RXChecksumValidated = s.RXChecksumVerified(bufs[i][:sizes[i]])
				}
				link.InjectInbound(ipv4.ProtocolNumber, p)
				p.DecRef()
			}
		}
	}()
	go func() {
		defer pumps.Done()
		packets := make([][]byte, 64)
		for {
			n := link.ReadBatch(ctx, packets)
			if n == 0 {
				return
			}
			if integrityHooksEnabled && f.integrity != nil {
				for _, p := range packets[:n] {
					f.integrity.packet("stack_output", p)
				}
			}
			if _, err := session.WriteBatch(packets[:n]); err != nil && ctx.Err() == nil {
				f.recordFault(err)
				t.Logf("TCP ring write: %v", err)
			}
			clear(packets[:n])
		}
	}()
	go func() {
		defer pumps.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				var n int64
				var err error
				if f.wordBoundaries != nil {
					n, err = f.wordBoundaries.echo(c)
				} else if integrityHooksEnabled && f.integrity != nil && f.integrity.selected("echo_read") {
					n, err = f.integrity.echo(c)
				} else {
					n, err = io.Copy(c, c)
				}
				if err != nil && ctx.Err() == nil {
					t.Logf("TCP echo ended: copied_bytes=%d error=%v", n, err)
				}
			}()
		}
	}()
	return func() {
		cancel()
		listener.Close()
		stack.Close()
		stack.Wait()
		link.Close()
		pumps.Wait()
		clients.Wait()
		detach()
		if f.integrity != nil {
			f.integrity.report(t)
			if err := f.integrity.err(); err != nil {
				t.Error(err)
			}
		}
	}
}

func tcpTransfer(t *testing.T, f *fixture, streams int, phase ...string) (float64, error) {
	if f.integrity == nil && !f.skipPayloadCapture {
		return tcpWordTransfer(t, f, streams, phase...)
	}
	return tcpLegacyTransfer(t, f, streams, phase...)
}

// Retained unchanged as the overhead oracle and for the existing tagged hunt.
func tcpLegacyTransfer(t *testing.T, f *fixture, streams int, phase ...string) (float64, error) {
	t.Helper()
	const size = 64 << 20
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i*13 + i/251)
	}
	want := sha256.Sum256(content)
	// Diagnostic payload generation is outside the timed region. Each stream
	// keeps the original single large Write, with its own immutable content.
	var contents [][]byte
	var references [][]byte
	var wants [][sha256.Size]byte
	transfer := integrityTransferID.Add(1)
	label := "transfer"
	if len(phase) != 0 {
		label = phase[0]
	}
	if f.integrity != nil {
		contents = make([][]byte, streams)
		references = make([][]byte, streams)
		wants = make([][sha256.Size]byte, streams)
		for stream := range streams {
			contents[stream] = make([]byte, size)
			id := transfer<<8 | uint64(stream+1)
			for i := range contents[stream] {
				contents[stream][i] = integrityByte(id, int64(i))
			}
			wants[stream] = sha256.Sum256(contents[stream])
			references[stream] = bytes.Clone(contents[stream])
		}
	}
	var wg sync.WaitGroup
	var diagnosticStack sync.Once
	failures := make(chan error, streams)
	diagnose := func(stage, local string, received int64, err error) {
		s, _ := f.io.(*Session)
		mode := "dll"
		if s != nil {
			mode = "ours"
		}
		// Capture the live session before closing a connection or stopping the
		// echo pumps. Teardown otherwise destroys the evidence of a stalled ring.
		report(t, map[string]any{"test": "tcp_failure_before_teardown", "arch": runtime.GOARCH, "mode": mode, "streams": streams, "stage": stage, "local": local, "received_bytes": received, "expected_bytes": size, "state": observeSession(s), "fault": fmt.Sprint(f.fault()), "error": err.Error()})
		diagnosticStack.Do(func() {
			buf := make([]byte, 1<<20)
			t.Logf("TCP failure goroutines:\n%s", buf[:runtime.Stack(buf, true)])
		})
	}
	finishResources := startCaptureResources(t, f)
	defer finishResources()
	start := ticks()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			content, want := content, want
			if f.integrity != nil {
				content, want = contents[i], wants[i]
			}
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.19.240.1")}, Timeout: 5 * time.Second}
			c, err := d.Dial("tcp4", "198.19.240.2:9002")
			if err != nil {
				diagnose("connect", "", 0, err)
				failures <- err
				return
			}
			defer c.Close()
			var identity *integrityConnection
			if f.integrity != nil {
				identity = f.integrity.bind(c.LocalAddr().String(), transfer<<8|uint64(i+1), fmt.Sprintf("repeat%s/%s/%s/transfer%d/streams%d", os.Getenv("NETSWITCH_WINTUN_INTEGRITY_REPEAT"), t.Name(), label, transfer, streams), references[i])
			}
			c.SetDeadline(time.Now().Add(30 * time.Second))
			type writeResult struct {
				n   int64
				err error
			}
			written := make(chan writeResult, 1)
			go func() {
				n, err := io.Copy(c, bytes.NewReader(content))
				written <- writeResult{n, err}
			}()
			digest := sha256.New()
			var receiver io.Reader = c
			var hostReader *integrityReader
			var capture *payloadCaptureReader
			if f.integrity != nil {
				hostReader = &integrityReader{reader: c, d: f.integrity, stage: "host_receive", local: c.LocalAddr().String(), connection: identity}
				if identity != nil {
					hostReader.fastReference = references[i]
				}
				receiver = hostReader
			} else if !f.skipPayloadCapture {
				capture = &payloadCaptureReader{reader: c, expected: content}
				receiver = capture
			}
			received, err := io.CopyN(digest, receiver, size)
			if capture != nil && capture.first != nil {
				report(t, map[string]any{"test": "tcp_payload_difference", "verdict": "integrity_failure", "mode": f.mode,
					"pair": performancePair(t.Name()), "test_path": t.Name(), "phase": label, "transfer_id": transfer,
					"stream_id": i, "local": c.LocalAddr().String(), "length": received, "expected_length": size,
					"difference": capture.first, "expected_sha256": fmt.Sprintf("%x", want), "actual_sha256": fmt.Sprintf("%x", digest.Sum(nil))})
			}
			if f.integrity != nil {
				f.integrity.hashes(identity, want[:], digest.Sum(nil), received, hostReader.reads)
			}
			if err != nil {
				diagnose("read", c.LocalAddr().String(), received, err)
				c.Close()
				sent := <-written
				failures <- fmt.Errorf("TCP transfer read %d/%d and wrote %d/%d bytes: %w", received, size, sent.n, size, errors.Join(err, sent.err))
				return
			}
			if sent := <-written; sent.err != nil {
				diagnose("write", c.LocalAddr().String(), received, sent.err)
				failures <- fmt.Errorf("TCP transfer wrote %d/%d bytes: %w", sent.n, size, sent.err)
				return
			}
			if !bytes.Equal(digest.Sum(nil), want[:]) {
				err := fmt.Errorf("%w: TCP payload hash mismatch: local=%s stream=%d expected=%x actual=%x", errPayloadIntegrity, c.LocalAddr(), i, want, digest.Sum(nil))
				diagnose("hash", c.LocalAddr().String(), received, err)
				failures <- err
			}
			if f.integrity != nil {
				f.integrity.complete(identity)
			}
		}()
	}
	wg.Wait()
	close(failures)
	var failure error
	for err := range failures {
		failure = errors.Join(failure, err)
	}
	if f.integrity != nil {
		failure = errors.Join(failure, f.integrity.err())
	}
	if failure != nil {
		return 0, failure
	}
	return float64(size*streams) / elapsed(start).Seconds() / 1e6, nil
}

// The sender/receiver runs in a separate process. Otherwise a Go packet session
// competes with the load generator for Go's Ps while the DLL's native work runs
// outside that limit, so saturation measures scheduler placement, not the link.
func udpTransfer(t *testing.T, streams int) (float64, error) {
	t.Helper()
	return runUDPClient(t, streams)
}

func udpTraffic(t *testing.T, streams int) (float64, error) {
	t.Helper()
	const size = 1200
	// UDP is lossy under saturation, particularly while a corrupted session
	// reopens. Measure delivered goodput for a fixed interval, with every
	// delivered payload checked. Do not wait forever for a dropped datagram.
	var senders, readers sync.WaitGroup
	var sent, received atomic.Uint64
	failures := make(chan error, streams*2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connections := make([]*net.UDPConn, streams)
	start := ticks()
	for id := 0; id < streams; id++ {
		c := udpSocket(t)
		connections[id] = c
		payload := bytes.Repeat([]byte{byte(id + 1)}, size)
		senders.Add(1)
		readers.Add(1)
		go func() {
			defer senders.Done()
			for ctx.Err() == nil {
				if _, err := c.Write(payload); err != nil {
					failures <- err
					return
				}
				sent.Add(1)
			}
		}()
		go func() {
			defer readers.Done()
			reply := make([]byte, size+1)
			for {
				n, err := c.Read(reply)
				if err != nil {
					var timeout net.Error
					if errors.As(err, &timeout) && timeout.Timeout() && ctx.Err() != nil {
						return
					}
					failures <- err
					return
				}
				if !bytes.Equal(reply[:n], payload) {
					failures <- fmt.Errorf("%w: UDP echo corruption", errPayloadIntegrity)
					return
				}
				received.Add(1)
			}
		}()
	}
	senders.Wait()
	for _, c := range connections {
		c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	}
	readers.Wait()
	for _, c := range connections {
		c.Close()
	}
	close(failures)
	var failure error
	for err := range failures {
		failure = errors.Join(failure, err)
	}
	seconds := elapsed(start).Seconds()
	report(t, map[string]any{"test": "udp_goodput", "arch": runtime.GOARCH, "streams": streams, "sent": sent.Load(), "received": received.Load(), "seconds": seconds})
	return float64(received.Load()*size) / seconds / 1e6, failure
}

func TestWintunUDPClient(t *testing.T) {
	requireRunner(t)
	streams := 0
	switch os.Getenv("NETSWITCH_WINTUN_UDP_STREAMS") {
	case "1":
		streams = 1
	case "8":
		streams = 8
	default:
		t.Skip("client process only")
	}
	rate, err := udpTraffic(t, streams)
	must(t, err)
	fmt.Printf("UDP_CLIENT_RESULT %.9f\n", rate)
}

func shortLatency(t *testing.T, mode string, session *Session) float64 {
	before := observeSession(session)
	c := udpSocket(t)
	defer c.Close()
	samples := make([]time.Duration, 20000)
	p := make([]byte, 64)
	b := make([]byte, 128)
	rescues := 0
	// Prime this socket, then measure a full burst rather than a fraction of
	// one scheduler time slice. The warm-up count is fixed for both paths.
	for i := -1000; i < len(samples); i++ {
		sequence := uint64(i + 1000)
		binary.LittleEndian.PutUint64(p, sequence)
		c.SetDeadline(time.Now().Add(250 * time.Millisecond))
		start := ticks()
		_, err := c.Write(p)
		must(t, err)
		rescued := false
		for {
			n, err := c.Read(b)
			if err != nil {
				var timeout net.Error
				if mode == "dll" && !rescued && errors.As(err, &timeout) && timeout.Timeout() {
					rescued = true
					rescues++
					c.SetDeadline(time.Now().Add(time.Second))
					_, err = c.Write(p)
					must(t, err)
					continue
				}
				must(t, err)
			}
			if n >= 8 && binary.LittleEndian.Uint64(b[:8]) < sequence {
				continue
			}
			if !bytes.Equal(b[:n], p) {
				t.Fatal(fmt.Errorf("%w: latency payload mismatch", errPayloadIntegrity))
			}
			break
		}
		if i >= 0 {
			samples[i] = elapsed(start)
		}
	}
	after := observeSession(session)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	// Report after measurement. A p95 alone cannot distinguish a wider latency
	// distribution from a long stall; do not stop the world in the timed loop.
	over50 := len(samples) - sort.Search(len(samples), func(i int) bool { return samples[i] > 50*time.Millisecond })
	report(t, map[string]any{"test": "burst_latency_sample", "arch": runtime.GOARCH, "mode": mode, "measured_round_trips": len(samples), "warmup_round_trips": 1000, "timeout_rescues": rescues, "p50_us": float64(samples[len(samples)/2]) / 1000, "p95_us": float64(samples[len(samples)*95/100]) / 1000, "p99_us": float64(samples[len(samples)*99/100]) / 1000, "max_ms": samples[len(samples)-1].Seconds() * 1000, "over_50_ms": over50, "state_before": before, "state_after": after})
	return float64(samples[len(samples)*95/100]) / 1000
}

func median(values []float64) float64 {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	mid := len(ordered) / 2
	if len(ordered)%2 != 0 {
		return ordered[mid]
	}
	return (ordered[mid-1] + ordered[mid]) / 2
}

// Run with the test binary's -test.cpuprofile flag. Keep the reference and our
// session in separate profiles so their CPU costs can be compared directly.
func TestWintunProfile(t *testing.T) {
	requireRunner(t)
	mode := os.Getenv("NETSWITCH_WINTUN_PROFILE")
	if mode != "dll" && mode != "ours" {
		t.Skip("explicit profile mode required")
	}
	f := newFixture(t, mode, 0)
	f.stopEcho()
	f.stopEcho = func() {}
	stop := tcpEcho(t, f)
	defer stop()
	for i := 0; i < 24; i++ {
		value, err := tcpTransfer(t, f, 1)
		must(t, err)
		t.Logf("profile %s transfer %d: %.2f MB/s", mode, i, value)
	}
}

// Both paths expose successful native read waits. The DLL does not expose its
// conditional write-event signals: count accepted WriteBatch calls separately,
// never label them as DLL signals. Sample before teardown wakes the reader.
func performanceCounters(io batchIO) (Stats, uint64) {
	switch s := io.(type) {
	case *Session:
		stats := s.Stats()
		return stats, stats.Wakeups // One signal per accepted nonempty batch.
	case *dllSession:
		return Stats{
			ReadPackets: s.readPackets.Load(), ReadWaits: s.readWaits.Load(),
			ReadWakes: s.readWakes.Load(), WrittenPackets: s.writtenPackets.Load(),
		}, s.writeBatches.Load()
	default:
		panic("unknown performance session")
	}
}

func pairedRatios(ours, dll []float64) ([]float64, error) {
	if len(ours) == 0 || len(ours) != len(dll) {
		return nil, fmt.Errorf("incomplete matched pairs: ours=%d DLL=%d", len(ours), len(dll))
	}
	for i := range ours {
		if ours[i] <= 0 || dll[i] <= 0 || math.IsNaN(ours[i]) || math.IsNaN(dll[i]) || math.IsInf(ours[i], 0) || math.IsInf(dll[i], 0) {
			return nil, fmt.Errorf("unusable pair %d: ours=%g DLL=%g", i, ours[i], dll[i])
		}
	}
	ratios := make([]float64, len(ours))
	for i := range ours {
		ratios[i] = ours[i] / dll[i]
	}
	return ratios, nil
}

// useProductionRegistrar makes the hashed release engine the registrar for
// the rest of the test when CI provides one, as production does. Otherwise
// the test binary keeps serving as its own registrar.
func useProductionRegistrar(t *testing.T, label string) {
	t.Helper()
	if os.Getenv(productionEngineEnv) == "" {
		return
	}
	engine := productionEngine(t)
	previous := registrarExecutable
	registrarExecutable = func() (string, error) { return engine.Path, nil }
	t.Cleanup(func() { registrarExecutable = previous })
	report(t, map[string]any{"test": label, "engine": engine})
}

// The reference is the signed DLL. NETSWITCH_WINTUN_REFERENCE=inprocess runs
// the same matched pairs and unchanged gate against the test-only in-process
// registration, isolating the registrar's cost from the DLL comparison.
func TestWintunPerformance(t *testing.T) {
	requireRunner(t)
	// Keep every matched sample and threshold unchanged, while making the
	// registration owner the exact release engine measured by the footprint
	// test. The packet loop still runs through these same shared rings.
	useProductionRegistrar(t, "performance_registrar_provenance")
	reference := "dll"
	switch os.Getenv("NETSWITCH_WINTUN_REFERENCE") {
	case "", "dll":
	case "inprocess":
		reference = "inprocess"
	default:
		t.Fatal("unknown NETSWITCH_WINTUN_REFERENCE")
	}
	const pairs = 12
	diagnostic := os.Getenv("NETSWITCH_WINTUN_INTEGRITY") == "1"
	if diagnostic && !integrityHooksEnabled {
		t.Fatal("integrity diagnostic requires -tags=wintun_integrity")
	}
	metrics := []struct {
		name    string
		streams int
		tcp     bool
	}{
		{"udp_p95_us", 0, false},
		{"udp_1_MBps", 1, false},
		{"udp_8_MBps", 8, false},
		{"tcp_1_MBps", 1, true},
		{"tcp_8_MBps", 8, true},
	}
	if os.Getenv("NETSWITCH_WINTUN_INTEGRITY_FOCUS") == "tcp_8_MBps" {
		if !diagnostic {
			t.Fatal("focused integrity runs require diagnostic mode")
		}
		metrics = metrics[len(metrics)-1:]
	}
	results := map[string]map[string][]performanceSample{"ours": {}, reference: {}}
	for _, metric := range metrics {
		for _, mode := range []string{"ours", reference} {
			results[mode][metric.name] = newPerformanceSamples(pairs, mode, metric.name)
		}
	}
	for trial := 0; trial < pairs; trial++ {
		t.Run(fmt.Sprintf("pair%d", trial), func(t *testing.T) {
			a := newAdapter(t, 0)
			modes := []string{"ours", reference}
			if trial%2 != 0 {
				modes = []string{reference, "ours"}
			}
			for _, metric := range metrics {
				// Match the SAME metric back to back, not two whole suites.
				for _, mode := range modes {
					t.Run(metric.name+"/"+mode, func(t *testing.T) {
						sample := &results[mode][metric.name][trial]
						// Registered first, runs after fixture teardown. Setup Fatals,
						// skips and teardown failures cannot leave a usable sample.
						t.Cleanup(func() {
							if (t.Failed() || t.Skipped()) && sample.cause == nil {
								sample.finish(0, fmt.Errorf("sample setup, execution or teardown failed; see subtest error"))
							}
							report(t, map[string]any{"test": "performance_sample", "diagnostic": diagnostic, "sample": sample, "verdict": integrityVerdict(sample.cause)})
						})
						f := fixtureOnAdapter(t, mode, a)
						if metric.tcp {
							f.stopEcho()
							f.stopEcho = tcpEcho(t, f)
							// Identical fixed warm-up, logged and excluded from
							// both measured samples; never retry a measured failure.
							for warm := 0; warm < 2; warm++ {
								rate, err := tcpTransfer(t, f, 1, fmt.Sprintf("warmup%d", warm))
								if err != nil {
									sample.finish(0, fmt.Errorf("warmup=%d: %w", warm, err))
								}
								must(t, err)
								report(t, map[string]any{"test": "tcp_warmup", "diagnostic": diagnostic, "arch": runtime.GOARCH, "mode": mode, "trial": trial, "streams": metric.streams, "warmup": warm, "MBps": rate})
							}
						}
						before, batchesBefore := performanceCounters(f.io)
						var value float64
						var err error
						switch {
						case metric.tcp:
							value, err = tcpTransfer(t, f, metric.streams, "measured")
						case metric.streams != 0:
							value, err = udpTransfer(t, metric.streams)
						default:
							session, _ := f.io.(*Session)
							value = shortLatency(t, mode, session)
						}
						after, batchesAfter := performanceCounters(f.io)
						packets, wakes := after.ReadPackets-before.ReadPackets, after.ReadWakes-before.ReadWakes
						written, batches := after.WrittenPackets-before.WrittenPackets, batchesAfter-batchesBefore
						sample.finish(value, errors.Join(err, f.fault()))
						diagnostics := map[string]any{
							"test": "performance", "diagnostic": diagnostic, "arch": runtime.GOARCH, "trial": trial, "mode": mode,
							"metric": metric.name, "sample": sample, "first": modes[0],
							"read_packets": packets, "read_wakeups": wakes,
							"read_waits":      after.ReadWaits - before.ReadWaits,
							"written_packets": written, "write_batches": batches,
							"error": fmt.Sprint(err), "fault": fmt.Sprint(f.fault()),
						}
						if wakes != 0 {
							diagnostics["read_packets_per_wakeup"] = float64(packets) / float64(wakes)
						}
						if batches != 0 {
							diagnostics["packets_per_write_batch"] = float64(written) / float64(batches)
						}
						if mode == "ours" {
							diagnostics["write_signals"] = after.Wakeups - before.Wakeups
						}
						report(t, diagnostics)
						// Report a failed reference too, but never turn an invalid
						// denominator into a favorable throughput ratio.
						must(t, sample.cause)
					})
				}
			}
		})
	}
	for _, metric := range metrics {
		ours, dll := results["ours"][metric.name], results[reference][metric.name]
		// Keep all positions, including fixture setup failures before a subtest.
		report(t, map[string]any{"test": "performance_samples", "diagnostic": diagnostic, "metric": metric.name, "ours": ours, "dll": dll})
		ratios, err := pairedSampleRatios(ours, dll, reference)
		if err != nil {
			t.Errorf("%s: %v", metric.name, err)
			continue
		}
		if diagnostic {
			// Instrumented timing never enters the clean performance gate.
			report(t, map[string]any{"test": "integrity_pairs_complete", "pairs": pairs, "metric": metric.name})
			continue
		}
		ratio := median(ratios)
		report(t, map[string]any{"test": "performance_paired", "statistic": "median_pair_ratio", "arch": runtime.GOARCH, "reference": reference, "pairs": pairs, "metric": metric.name, "ratio": ratio, "pair_ratios": ratios, "dll_samples": dll, "ours_samples": ours})
		if metric.name == "udp_p95_us" {
			if ratio > 1.10 {
				t.Errorf("latency regression: median matched ratio %.3f > 1.10", ratio)
			}
		} else if ratio < 0.90 {
			t.Errorf("throughput regression %s: median matched ratio %.3f < 0.90", metric.name, ratio)
		}
	}
}

func TestWintunBatchCost(t *testing.T) {
	requireRunner(t)
	for _, batch := range []int{1, 8, 64} {
		r, err := allocateRings(MinCapacity)
		must(t, err)
		r.writeEvent, err = windows.CreateEvent(nil, 0, 0, nil)
		must(t, err)
		packets := make([][]byte, batch)
		for i := range packets {
			packets[i] = make([]byte, 1228)
		}
		const samples = 20000
		var total time.Duration
		for i := 0; i < samples; i++ {
			r.receive.store(0, r.tail) // Simulate the driver's consumption outside timing.
			start := ticks()
			n, drops, err := r.write(packets)
			total += elapsed(start)
			if err != nil || n != batch || drops != 0 {
				t.Fatalf("batch: %d %d %v", n, drops, err)
			}
			result, err := windows.WaitForSingleObject(r.writeEvent, 0)
			must(t, err)
			if result != windows.WAIT_OBJECT_0 {
				t.Fatal("missing batch wake")
			}
		}
		must(t, r.close())
		report(t, map[string]any{"test": "batch_cost", "arch": runtime.GOARCH, "batch": batch, "packet_bytes": 1228, "samples": samples, "ns_per_batch": float64(total.Nanoseconds()) / samples, "ns_per_packet": float64(total.Nanoseconds()) / float64(samples*batch)})
	}
}
