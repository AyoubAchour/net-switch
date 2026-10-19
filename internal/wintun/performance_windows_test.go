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
	link := ns.NewLink()
	stack, err := ns.New(link, ns.DefaultOptions())
	must(t, err)
	address := tcpip.AddrFrom4([4]byte{198, 19, 240, 2})
	if e := stack.AddProtocolAddress(ns.NIC, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: address, PrefixLen: 30}}, gv.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	listener, err := gonet.ListenTCP(stack, tcpip.FullAddress{NIC: ns.NIC, Addr: address, Port: 9002}, ipv4.ProtocolNumber)
	must(t, err)
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
			if _, err := session.WriteBatch(packets[:n]); err != nil && ctx.Err() == nil {
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
				io.Copy(c, c)
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
	}
}

func tcpTransfer(t *testing.T, streams int) (float64, error) {
	t.Helper()
	const size = 64 << 20
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i*13 + i/251)
	}
	want := sha256.Sum256(content)
	var wg sync.WaitGroup
	failures := make(chan error, streams)
	start := ticks()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.19.240.1")}, Timeout: 5 * time.Second}
			c, err := d.Dial("tcp4", "198.19.240.2:9002")
			if err != nil {
				failures <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			written := make(chan error, 1)
			go func() { _, err := io.Copy(c, bytes.NewReader(content)); written <- err }()
			digest := sha256.New()
			_, err = io.CopyN(digest, c, size)
			if err != nil {
				c.Close()
				<-written
				failures <- err
				return
			}
			if err = <-written; err != nil {
				failures <- err
				return
			}
			if !bytes.Equal(digest.Sum(nil), want[:]) {
				failures <- fmt.Errorf("TCP payload hash mismatch")
			}
		}()
	}
	wg.Wait()
	close(failures)
	var failure error
	for err := range failures {
		failure = errors.Join(failure, err)
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
					failures <- fmt.Errorf("UDP echo corruption")
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

func shortLatency(t *testing.T, mode string) float64 {
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
				t.Fatal("latency payload mismatch")
			}
			break
		}
		if i >= 0 {
			samples[i] = elapsed(start)
		}
	}
	report(t, map[string]any{"test": "burst_latency_sample", "arch": runtime.GOARCH, "mode": mode, "measured_round_trips": len(samples), "warmup_round_trips": 1000, "timeout_rescues": rescues})
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
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
		value, err := tcpTransfer(t, 1)
		must(t, err)
		t.Logf("profile %s transfer %d: %.2f MB/s", mode, i, value)
	}
}

func TestWintunPerformance(t *testing.T) {
	requireRunner(t)
	results := map[string]map[string][]float64{"dll": {}, "ours": {}}
	// Balance order across six pairs, then pool all samples. Hosted runners
	// vary by about 30%; no individual pair is a 10% regression gate. Compare
	// medians so one runner pause cannot dominate either implementation's score.
	const pairs = 6
	for trial := 0; trial < pairs; trial++ {
		modes := []string{"dll", "ours"}
		if trial%2 != 0 {
			modes = []string{"ours", "dll"}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("trial%d/%s", trial, mode), func(t *testing.T) {
				f := newFixture(t, mode, 0)
				measure := func(name string, value float64) {
					results[mode][name] = append(results[mode][name], value)
					report(t, map[string]any{"test": "performance", "arch": runtime.GOARCH, "trial": trial, "mode": mode, "metric": name, "value": value})
				}
				measure("udp_p95_us", shortLatency(t, mode))
				for _, streams := range []int{1, 8} {
					var before Stats
					if s, ok := f.io.(*Session); ok {
						before = s.Stats()
					}
					value, err := udpTransfer(t, streams)
					must(t, err)
					if s, ok := f.io.(*Session); ok {
						after := s.Stats()
						packets, wakes := after.WrittenPackets-before.WrittenPackets, after.Wakeups-before.Wakeups
						if wakes == 0 {
							t.Fatal("UDP comparison wrote no batches")
						}
						report(t, map[string]any{"test": "udp_batching", "arch": runtime.GOARCH, "trial": trial, "streams": streams, "written_packets": packets, "wakeups": wakes, "packets_per_wakeup": float64(packets) / float64(wakes)})
					}
					if fault := f.fault(); fault != nil {
						if mode != "dll" || !errors.Is(fault, windows.ERROR_INVALID_DATA) {
							t.Fatal(fault)
						}
						// Retain the partial/failed DLL measurement. Only restart for
						// the NEXT metric, never rerun a failed sample into a pass.
						report(t, map[string]any{"test": "baseline_driver_failure", "arch": runtime.GOARCH, "trial": trial, "metric": fmt.Sprintf("udp_%d_MBps", streams), "error": fault.Error(), "recorded_MBps": value})
						f.stopEcho()
						must(t, f.io.Close())
						f.io = startIO(t, f.a, mode)
						f.faultMu.Lock()
						f.lastFault = nil
						f.faultMu.Unlock()
						f.startEcho(t)
					}
					measure(fmt.Sprintf("udp_%d_MBps", streams), value)
				}
				f.stopEcho()
				f.stopEcho = func() {}
				for _, streams := range []int{1, 8} {
					var value float64
					var err error
					var before Stats
					func() {
						stop := tcpEcho(t, f)
						defer stop()
						// Profiles show both stacks warming over their first two
						// connections. The engine is long-lived: compare steady
						// throughput after a fixed, visible warm-up for both paths.
						for warm := 0; warm < 2; warm++ {
							rate, warmErr := tcpTransfer(t, 1)
							must(t, warmErr)
							report(t, map[string]any{"test": "tcp_warmup", "arch": runtime.GOARCH, "mode": mode, "trial": trial, "streams": streams, "warmup": warm, "MBps": rate})
						}
						if s, ok := f.io.(*Session); ok {
							before = s.Stats()
						}
						value, err = tcpTransfer(t, streams)
					}()
					if err != nil {
						if mode != "dll" || !errors.Is(f.fault(), windows.ERROR_INVALID_DATA) {
							t.Fatal(err)
						}
						report(t, map[string]any{"test": "baseline_driver_failure", "arch": runtime.GOARCH, "trial": trial, "metric": fmt.Sprintf("tcp_%d_MBps", streams), "error": f.fault().Error(), "recorded_MBps": 0})
						must(t, f.io.Close())
						f.io = startIO(t, f.a, mode)
						f.faultMu.Lock()
						f.lastFault = nil
						f.faultMu.Unlock()
					}
					measure(fmt.Sprintf("tcp_%d_MBps", streams), value)
					if s, ok := f.io.(*Session); ok {
						after := s.Stats()
						report(t, map[string]any{"test": "tcp_batching", "arch": runtime.GOARCH, "trial": trial, "streams": streams, "written_packets": after.WrittenPackets - before.WrittenPackets, "wakeups": after.Wakeups - before.Wakeups})
					}
				}
			})
		}
	}
	for metric, dllValues := range results["dll"] {
		ownValues := results["ours"][metric]
		if len(dllValues) != pairs || len(ownValues) != pairs {
			t.Errorf("incomplete comparison: %s", metric)
			continue
		}
		dll, own := median(dllValues), median(ownValues)
		if dll == 0 {
			t.Errorf("DLL median is zero for %s; no usable performance comparison", metric)
			continue
		}
		report(t, map[string]any{"test": "performance_pooled", "statistic": "median", "arch": runtime.GOARCH, "pairs": pairs, "metric": metric, "dll": dll, "ours": own, "ratio": own / dll, "dll_samples": dllValues, "ours_samples": ownValues})
		if metric == "udp_p95_us" {
			if own > dll*1.10 {
				t.Errorf("latency regression: ours %.2f, DLL %.2f us", own, dll)
			}
		} else if own < dll*0.90 {
			t.Errorf("throughput regression %s: ours %.2f, DLL %.2f MB/s", metric, own, dll)
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
