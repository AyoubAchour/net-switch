//go:build windows

package wintun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

func tcpEcho(t *testing.T, session batchIO) func() {
	t.Helper()
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
				return
			}
			for i := 0; i < n; i++ {
				p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(bufs[i][:sizes[i]]))})
				link.InjectInbound(ipv4.ProtocolNumber, p)
				p.DecRef()
			}
		}
	}()
	go func() {
		defer pumps.Done()
		for {
			p := link.Read(ctx)
			if p == nil {
				return
			}
			if _, err := session.WriteBatch([][]byte{p}); err != nil && ctx.Err() == nil {
				t.Logf("TCP ring write: %v", err)
			}
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

func tcpTransfer(t *testing.T, streams int) float64 {
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
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	return float64(size*streams) / elapsed(start).Seconds() / 1e6
}

func udpTransfer(t *testing.T, streams int) float64 {
	t.Helper()
	const rounds = 2048
	const window = 16
	const size = 1200
	var wg sync.WaitGroup
	failures := make(chan error, streams)
	start := ticks()
	for id := 0; id < streams; id++ {
		c := udpSocket(t)
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer c.Close()
			payload := bytes.Repeat([]byte{byte(id + 1)}, size)
			reply := make([]byte, size+1)
			for round := 0; round < rounds; round++ {
				c.SetDeadline(time.Now().Add(2 * time.Second))
				for i := 0; i < window; i++ {
					if _, err := c.Write(payload); err != nil {
						failures <- err
						return
					}
				}
				for i := 0; i < window; i++ {
					n, err := c.Read(reply)
					if err != nil {
						failures <- err
						return
					}
					if !bytes.Equal(reply[:n], payload) {
						failures <- fmt.Errorf("UDP echo corruption")
						return
					}
				}
			}
		}(id)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	return float64(streams*rounds*window*size) / elapsed(start).Seconds() / 1e6
}

func shortLatency(t *testing.T) float64 {
	c := udpSocket(t)
	defer c.Close()
	samples := make([]time.Duration, 2000)
	p := []byte("latency comparison")
	b := make([]byte, 64)
	for i := range samples {
		c.SetDeadline(time.Now().Add(time.Second))
		start := ticks()
		_, err := c.Write(p)
		must(t, err)
		n, err := c.Read(b)
		must(t, err)
		if !bytes.Equal(b[:n], p) {
			t.Fatal("latency payload mismatch")
		}
		samples[i] = elapsed(start)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return float64(samples[len(samples)*95/100]) / 1000
}

func median(values []float64) float64 { sort.Float64s(values); return values[len(values)/2] }

func TestWintunPerformance(t *testing.T) {
	requireRunner(t)
	results := map[string]map[string][]float64{"dll": {}, "ours": {}}
	// Alternate order across three independent trials to expose warm-up or
	// runner noise. Compare medians; retain every raw measurement in the log.
	for trial := 0; trial < 3; trial++ {
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
				measure("udp_p95_us", shortLatency(t))
				for _, streams := range []int{1, 8} {
					measure(fmt.Sprintf("udp_%d_MBps", streams), udpTransfer(t, streams))
				}
				f.stopEcho()
				f.stopEcho = func() {}
				stop := tcpEcho(t, f.io)
				defer stop()
				for _, streams := range []int{1, 8} {
					measure(fmt.Sprintf("tcp_%d_MBps", streams), tcpTransfer(t, streams))
				}
			})
		}
	}
	for metric, dllValues := range results["dll"] {
		ownValues := results["ours"][metric]
		if len(dllValues) != 3 || len(ownValues) != 3 {
			t.Errorf("incomplete comparison: %s", metric)
			continue
		}
		dll, own := median(dllValues), median(ownValues)
		report(t, map[string]any{"test": "performance_median", "arch": runtime.GOARCH, "metric": metric, "dll": dll, "ours": own, "ratio": own / dll})
		if metric == "udp_p95_us" {
			if own > dll*1.10 {
				t.Errorf("latency regression: ours %.2f, DLL %.2f us", own, dll)
			}
		} else if own < dll*0.90 {
			t.Errorf("throughput regression %s: ours %.2f, DLL %.2f MB/s", metric, own, dll)
		}
	}
}
