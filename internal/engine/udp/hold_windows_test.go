//go:build windows

package udp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"github.com/AyoubAchour/net-switch/internal/winclock"
)

type heldOwners struct {
	*testfake.Owners
	entered chan context.Context
}

func (*heldOwners) UDPLookupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return winclock.System.WithTimeout(parent, 250*time.Millisecond)
}
func (o *heldOwners) UDP(ctx context.Context, key netip.AddrPort) (platform.Owner, error) {
	o.entered <- ctx
	return o.Owners.UDP(ctx, key)
}

func TestHeldUDPSetupKeepsBudgetAndReconcilesUnknown(t *testing.T) {
	gate := make(chan struct{})
	o := &heldOwners{Owners: &testfake.Owners{Value: platform.Owner{Generation: owner.Generation}, Err: context.DeadlineExceeded, Gate: gate}, entered: make(chan context.Context, 1)}
	n, c, sockets, _, ids, _ := setup(t, o.Owners)
	n.owners = o
	// A global budget smaller than the per-session packet budget must still
	// hold while generation is pending. Charge both payload and ICMP quote.
	c.Limit = 3 * 30
	send(n, dest, []byte("x"))
	ctx := await(t, o.entered)
	winclock.System.Wait(t.Context(), 70*time.Millisecond)
	if ctx.Err() != nil || c.Resolved.Load() != 0 {
		t.Fatalf("NAT cut off the platform's hold: %v", ctx.Err())
	}
	for range 5 {
		send(n, dest, []byte("x"))
	}
	// Overflowing the destroy-event buffer forces an immediate snapshot.
	// Its newly known identity must not invalidate our unknown admission.
	for range 33 {
		n.Destroy(local, "unrelated generation")
	}
	if c.Pending.Load() != c.Limit || n.Dropped.Load() != 3 {
		t.Fatalf("held queue escaped budget: pending=%d dropped=%d", c.Pending.Load(), n.Dropped.Load())
	}
	close(gate)
	s := await(t, sockets)
	for range 3 {
		await(t, s.out)
	}
	if c.Resolved.Load() != 1 || n.GenerationMissing.Load() != 0 {
		t.Fatal("generation-bearing unknown owner was not admitted")
	}
	// The live dump now knows the identity: the admitted unknown session
	// must survive. A subsequent socket generation change must close it.
	ids.set(owner)
	n.Reconcile(t.Context())
	send(n, dest, []byte("still live"))
	if got := await(t, s.out); string(got.b) != "still live" {
		t.Fatal("existing unknown flow was cut")
	}
	replacement := owner
	replacement.Generation = "replacement"
	ids.set(replacement)
	n.Reconcile(t.Context())
	await(t, s.done)
	n.Close()
	if c.Pending.Load() != 0 || c.Closed.Load() != 1 {
		t.Fatalf("held setup leaked its budget: pending=%d tickets=%d", c.Pending.Load(), c.Closed.Load())
	}
}

func TestHeldUDPSetupTimeoutRefusesAndReleasesBudget(t *testing.T) {
	o := &heldOwners{Owners: &testfake.Owners{Value: owner, Gate: make(chan struct{})}, entered: make(chan context.Context, 1)}
	n, c, _, out, _, calls := setup(t, o.Owners)
	n.owners = o
	start := winclock.Now()
	send(n, dest, []byte("held"))
	await(t, o.entered)
	if c.Pending.Load() == 0 {
		t.Fatal("fixture never held datagram storage")
	}
	await(t, out)
	if winclock.Since(start) < 250*time.Millisecond {
		t.Fatal("setup was refused at the old 50 ms bound")
	}
	n.Close()
	if n.GenerationMissing.Load() != 1 || c.Resolved.Load() != 0 || calls.Load() != 0 || c.Pending.Load() != 0 || c.Closed.Load() != 1 {
		t.Fatalf("timeout admitted or leaked: missing=%d resolved=%d opens=%d bytes=%d closed=%d", n.GenerationMissing.Load(), c.Resolved.Load(), calls.Load(), c.Pending.Load(), c.Closed.Load())
	}
}
