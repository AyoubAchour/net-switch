package stack

import (
	"context"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestLinkQueue(t *testing.T) {
	l := NewLink()
	defer l.Close()
	p := []byte{42}
	for range QueuePackets {
		if !l.Send(p) {
			t.Fatal("early drop")
		}
	}
	p[0] = 99
	if l.Send(p) || l.Dropped.Load() != 1 {
		t.Fatal("full queue did not drop")
	}
	for range QueuePackets {
		if got := l.Read(context.Background()); len(got) != 1 || got[0] != 42 {
			t.Fatal("borrowed buffer retained")
		}
	}
	if l.Send(make([]byte, MTU+1)) {
		t.Fatal("oversize accepted")
	}
	l.Close()
	if l.Send(p) || l.Read(context.Background()) != nil {
		t.Fatal("closed queue active")
	}
}

func TestLinkConcurrentClose(t *testing.T) {
	l := NewLink()
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for range 200 {
				l.Send([]byte{1})
			}
		})
	}
	wg.Go(l.Close)
	wg.Wait()
}

func TestStackOptions(t *testing.T) {
	o := DefaultOptions()
	o.ClockResolution = 500 * time.Microsecond
	s, err := New(NewLink(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wait()
	defer s.Close()
	var cc tcpip.CongestionControlOption
	var tw tcpip.TCPTimeWaitTimeoutOption
	var rx tcpip.TCPReceiveBufferSizeRangeOption
	var tx tcpip.TCPSendBufferSizeRangeOption
	for _, opt := range []tcpip.GettableTransportProtocolOption{&cc, &tw, &rx, &tx} {
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			t.Fatal(err)
		}
	}
	if cc != "cubic" || time.Duration(tw) != o.TimeWait || rx.Default != 1<<20 || rx.Max != 8<<20 || tx.Default != 1<<20 || tx.Max != 6<<20 || s.ClockResolution() != o.ClockResolution {
		t.Fatalf("options: %s %v %+v %+v %s", cc, tw, rx, tx, s.ClockResolution())
	}
}
