//go:build windows

package udp

import (
	"context"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

// The native Windows test has observed equal creation timestamps after a
// same-process close/reopen. Model that exact identity here, deterministically,
// through the real policy table, NAT and reconnect/cap closure selectors.
func TestWindowsTimestampCollisionPreservesPolicyAndExplicitClosures(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "repin then reconnect", true: "cap blocks existing line"}[blocked], func(t *testing.T) {
			config := policy.Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, AppLines: map[string]string{owner.AppID: "A"}}
			table := flows.New(flows.Defaults(), nil)
			apply := func(revision uint64) policy.Applied {
				t.Helper()
				applied, err := table.Apply(policy.Revision{N: revision, Hash: policy.Hash(config), Config: config})
				if err != nil {
					t.Fatal(err)
				}
				return applied
			}
			apply(1)
			owners := &liveOwner{value: owner} // Same PID/start/path/timestamp throughout.
			sockets, lines := make(chan *socket, 4), make(chan string, 4)
			output := make(chan []byte, 4)
			dialer := testfake.Dialer{UDPFunc: func(_ context.Context, line string, _ bool) (platform.UDPConn, error) {
				socket := newSocket()
				sockets <- socket
				lines <- line
				return socket, nil
			}}
			nat := New(context.Background(), nil, table, owners, owners, dialer, testfake.Output{Packets: output}, 9000)
			defer nat.Close()
			send(nat, dest, []byte("before close/reopen"))
			original := await(t, sockets)
			await(t, original.out)
			if await(t, lines) != "A" {
				t.Fatal("initial pin missed")
			}
			if blocked {
				config.Blocked = []string{"A"}
			} else {
				config.AppLines[owner.AppID] = "B"
			}
			revision := apply(2)
			nat.Reconcile(context.Background())
			if !blocked {
				send(nat, dest, []byte("same timestamp after repin"))
				if packet := await(t, original.out); string(packet.b) != "same timestamp after repin" {
					t.Fatal("the surviving session did not retain its old line")
				}
			}
			selector := flows.Selector{App: owner.AppID, NotLine: "B"}
			before := uint64(0)
			if blocked {
				selector, before = flows.Selector{Line: "A"}, revision.Point
			}
			result, err := table.CloseFlows(selector, before)
			if err != nil || result.Closed != 1 || result.Failed != 0 {
				t.Fatalf("explicit closure missed the collided session: %+v %v", result, err)
			}
			await(t, original.done)
			send(nat, dest, []byte("after explicit closure"))
			if blocked {
				await(t, output)
				select {
				case <-sockets:
					t.Fatal("blocked replacement opened an egress socket")
				default:
				}
			} else {
				replacement := await(t, sockets)
				await(t, replacement.out)
				if await(t, lines) != "B" {
					t.Fatal("Reconnect did not apply the new pin")
				}
			}
		})
	}
}
