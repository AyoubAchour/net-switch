package engine

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestStartRollbackAndDisconnectLifetime(t *testing.T) {
	for _, fail := range []string{"prepare", "capture", ""} {
		t.Run(fail, func(t *testing.T) {
			tun := testfake.NewTun()
			routes := &testfake.Routes{Fail: fail}
			e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := policy.Config{Lines: []platform.Line{{ID: "A"}}}
			_, err := e.Start(ctx, policy.Revision{N: 1, Hash: policy.Hash(c), Config: c})
			if fail != "" {
				if err == nil || e.Table.Applied() != nil || routes.Calls[len(routes.Calls)-1] != "cleanup" {
					t.Fatal("start failure did not roll back")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			if e.Table.Applied() == nil {
				t.Fatal("controller disconnect stopped routing")
			}
			if routes.Calls[len(routes.Calls)-1] != "capture" {
				t.Fatal("capture was not last")
			}
			if err := e.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Table.Applied() != nil {
				t.Fatal("stop kept loaded revision")
			}
		})
	}
}

type batchTun struct {
	*testfake.Tun
	batches chan []string
	release chan struct{}
}

func (t *batchTun) WriteBatch(packets [][]byte) (int, error) {
	var copyOf []string
	for _, p := range packets {
		copyOf = append(copyOf, string(p))
	}
	t.batches <- copyOf
	select {
	case <-t.release:
	case <-t.Done:
	}
	return len(packets), nil
}

func (*batchTun) RXChecksumVerified(p []byte) bool { return p[19] == 2 }

func TestEngineUsesAvailableBatchesAndChecksumMetadata(t *testing.T) {
	tun := &batchTun{Tun: testfake.NewTun(), batches: make(chan []string, 2), release: make(chan struct{}, 2)}
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: &testfake.Routes{}, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
	defer e.Stop(context.Background())
	c := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}); err != nil {
		t.Fatal(err)
	}
	next := func(want []string) {
		t.Helper()
		select {
		case got := <-tun.batches:
			if !slices.Equal(got, want) {
				t.Fatalf("batch %v, want %v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("writer did not deliver available packets")
		}
	}
	e.link.Send([]byte("one"))
	next([]string{"one"})
	e.link.Send([]byte("two"))
	e.link.Send([]byte("three"))
	tun.release <- struct{}{}
	next([]string{"two", "three"})
	tun.release <- struct{}{}
	verified := make(chan bool, 2)
	e.link.SetObserver(func(p *gv.PacketBuffer) { verified <- p.RXChecksumValidated })
	for _, dst := range []string{"198.18.0.2", "198.18.0.3"} {
		tun.In <- packet.IP(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr(dst), 253, []byte("metadata"))
	}
	for _, want := range []bool{true, false} {
		select {
		case got := <-verified:
			if got != want {
				t.Fatalf("checksum metadata %v, want %v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("reader did not pass checksum metadata")
		}
	}
}

type preparedRoutes struct {
	testfake.Routes
	lines []platform.Line
}

func (r *preparedRoutes) Prepare(ctx context.Context, lines []platform.Line) error {
	r.lines = append([]platform.Line(nil), lines...)
	return r.Routes.Prepare(ctx, lines)
}

type failSecondSave struct{ count int }

func (s *failSecondSave) SaveApplied(policy.Applied) error {
	s.count++
	if s.count == 2 {
		return errors.New("state fsync failed")
	}
	return nil
}
func TestApplyRestoresRoutesOnPersistenceFailure(t *testing.T) {
	routes := &preparedRoutes{}
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return testfake.NewTun(), nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), &failSecondSave{})
	defer e.Stop(context.Background())
	c := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	r := policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}
	if _, err := e.Start(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.N = 2
	r.Config.Lines = []platform.Line{{ID: "B"}}
	r.Hash = policy.Hash(r.Config)
	if _, err := e.Apply(context.Background(), r); err == nil {
		t.Fatal("persistence failure acknowledged")
	}
	if routes.lines[0].ID != "A" || e.Table.Applied().N != 1 {
		t.Fatal("route state differs from loaded policy")
	}
}
