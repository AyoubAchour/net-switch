//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func occupiedScanQueue(t *testing.T) (*Owners, socketRow, holder) {
	t.Helper()
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	var metadata unix.Stat_t
	var statErr error
	if err := raw.Control(func(value uintptr) { fd = int(value); statErr = unix.Fstat(fd, &metadata) }); err != nil || statErr != nil {
		t.Fatalf("live socket metadata: %v %v", err, statErr)
	}
	pid := uint32(os.Getpid())
	start, err := processStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	o.rememberPID(metadata.Uid, pid)
	for range cap(o.scanSlots) {
		o.scanSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for len(o.scanSlots) > 0 {
			o.endScan()
		}
	})
	return o, socketRow{protocol: unix.IPPROTO_UDP, inode: uint32(metadata.Ino), uid: metadata.Uid}, holder{pid: pid, start: start, fd: strconv.Itoa(fd)}
}

func TestScanQueueUsesTheExistingLookupDeadline(t *testing.T) {
	o, _, _ := occupiedScanQueue(t)
	ctx, cancel := lookupContext(context.Background())
	defer cancel()
	acquired, err := o.beginScan(ctx, nil)
	if acquired || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("occupied queue did not honor the original lookup deadline: %v", err)
	}
	if o.scanQueueWaits.Load() != 1 || o.scanQueueTimeouts.Load() != 1 || len(o.scanSlots) != cap(o.scanSlots) {
		t.Fatalf("queue was not occupied throughout: waits=%d timeouts=%d slots=%d/%d", o.scanQueueWaits.Load(), o.scanQueueTimeouts.Load(), len(o.scanSlots), cap(o.scanSlots))
	}
}

func TestPublishedHolderWakesLookupWithoutAScannerSlot(t *testing.T) {
	o, row, h := occupiedScanQueue(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		owner platform.Owner
		err   error
	}
	done := make(chan result, 1)
	go func() {
		owner, err := o.holders(ctx, row)
		done <- result{owner, err}
	}()
	until := time.Now().Add(time.Second)
	for o.scanQueueWaits.Load() == 0 && time.Now().Before(until) {
		runtime.Gosched()
	}
	if o.scanQueueWaits.Load() == 0 {
		t.Fatal("fixture never reached the occupied scan queue")
	}
	o.publish(map[uint32]holder{row.inode: h})
	select {
	case got := <-done:
		if got.err != nil || got.owner.PID != h.pid || got.owner.StartTime != h.start {
			t.Fatalf("published live owner: %+v %v", got.owner, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("a published holder remained blocked behind unrelated scans")
	}
	if len(o.scanSlots) != cap(o.scanSlots) || o.scanQueueTimeouts.Load() != 0 {
		t.Fatal("fixture released a scan slot or lookup timed out before validation")
	}
}
