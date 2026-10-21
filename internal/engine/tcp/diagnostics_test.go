package tcp

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

func TestDiagnosticsIdentifyBothLegsAndSurviveClose(t *testing.T) {
	peer := newReadyPeer()
	f, dial := harness(t, &testfake.Controller{Line: "A"}, testfake.Dialer{
		TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) { return peer, nil },
	})
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	select {
	case <-peer.watching:
	case <-time.After(time.Second):
		t.Fatal("relay did not start")
	}
	// Watch precedes publication. Wait for that publication without depending
	// on a fixed scheduler delay, then check the actual app/native addresses.
	deadline := time.Now().Add(time.Second)
	var d []Diagnostic
	for time.Now().Before(deadline) {
		d, _ = f.Diagnostics(128)
		if len(d) == 1 && d[0].NativeLocal != "" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(d) != 1 || d[0].Source != app.LocalAddr().String() || d[0].Destination != app.RemoteAddr().String() ||
		d[0].NativeLocal != peer.LocalAddr().String() || d[0].ReceiveGrant != MinimumBuffer || d[0].SendGrant != MinimumBuffer {
		t.Fatalf("diagnostics lost a TCP leg or its grants: %+v", d)
	}
	if rows, omitted := f.Diagnostics(0); len(rows) != 0 || omitted != 1 {
		t.Fatalf("bounded snapshot: rows=%d omitted=%d", len(rows), omitted)
	}
	// The close path may retire/remove an endpoint while a stats caller still
	// holds its snapshot. Exercise that lifetime under the shared race jobs.
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			f.Diagnostics(128)
		}
	})
	f.Stop()
	f.Wait()
	wg.Wait()
}
