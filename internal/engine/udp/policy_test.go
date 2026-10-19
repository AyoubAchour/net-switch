package udp

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type liveOwner struct {
	mu    sync.Mutex
	value platform.Owner
}

func (o *liveOwner) TCP(context.Context, platform.Tuple) (platform.Owner, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.value, nil
}
func (o *liveOwner) UDP(context.Context, netip.AddrPort) (platform.Owner, error) {
	return o.TCP(context.Background(), platform.Tuple{})
}
func (o *liveOwner) Snapshot(context.Context, []netip.AddrPort) (map[netip.AddrPort]platform.Owner, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return map[netip.AddrPort]platform.Owner{local: o.value}, nil
}
func (o *liveOwner) replace(v platform.Owner) { o.mu.Lock(); o.value = v; o.mu.Unlock() }

func TestReusedPortChangesPinAndRejectsBlockedOwnerUnderTraffic(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "opposite pin", true: "blocked pin"}[blocked], func(t *testing.T) {
			c := policy.Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, AppLines: map[string]string{"first": "A", "second": "B"}}
			if blocked {
				c.Blocked = []string{"B"}
			}
			table := flows.New(flows.Defaults(), nil)
			if _, err := table.Apply(policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}); err != nil {
				t.Fatal(err)
			}
			owners := &liveOwner{value: owner}
			sockets := make(chan *socket, 4)
			lines := make(chan string, 4)
			out := make(chan []byte, 1024)
			dialer := testfake.Dialer{UDPFunc: func(_ context.Context, line string, _ bool) (platform.UDPConn, error) {
				s := newSocket()
				sockets <- s
				lines <- line
				return s, nil
			}}
			n := New(context.Background(), nil, table, owners, owners, dialer, testfake.Output{Packets: out}, 9000)
			defer n.Close()
			send(n, dest, []byte("first"))
			old := await(t, sockets)
			await(t, old.out)
			if await(t, lines) != "A" {
				t.Fatal("first pin missed")
			}
			ctx, cancel := context.WithCancel(context.Background())
			var traffic sync.WaitGroup
			traffic.Go(func() {
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
						send(n, dest, []byte("continuous"))
					}
				}
			})
			defer func() { cancel(); traffic.Wait() }()
			next := owner
			next.AppID = "second"
			next.Generation = "replacement"
			owners.replace(next)
			start := time.Now()
			// Deliberately lose the destroy event. Reconciliation alone must repair
			// an endpoint that is continuously sending, not just an idle one.
			n.Reconcile(context.Background())
			if blocked {
				await(t, out)
				select {
				case <-sockets:
					t.Fatal("blocked replacement dialed")
				default:
				}
			} else {
				fresh := await(t, sockets)
				await(t, fresh.out)
				if await(t, lines) != "B" {
					t.Fatal("replacement kept first pin")
				}
				n.Destroy(local, "socket1")
				select {
				case <-fresh.done:
					t.Fatal("delayed destroy killed replacement")
				default:
				}
			}
			if time.Since(start) > time.Second {
				t.Fatal("reuse decision exceeded accepted window")
			}
		})
	}
}

func TestPacketArrivingAfterRejectFlushIsAlsoRejected(t *testing.T) {
	gate := make(chan struct{})
	n, _, _, out, _, _ := setup(t, &testfake.Owners{Value: owner, Gate: gate})
	send(n, dest, []byte("before flush"))
	b := n.bucket(local)
	b.Lock()
	s := b.m[local]
	b.Unlock()
	s.rejectPending(owner.AppID)
	await(t, out)
	send(n, dest, []byte("after flush"))
	await(t, out)
	n.Close()
	close(gate)
}
