//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func sharedBatchSocket(t *testing.T) (socketRow, holder, holder, descriptorBatchKey, descriptorBatchResult) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := diagDump(ctx, unix.AF_INET, unix.IPPROTO_UDP, c.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	row, err := matchUDP(rows, c.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := raw.Control(func(value uintptr) { fd = int(value) }); err != nil {
		t.Fatal(err)
	}
	parentStart, err := processStart(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	a := holder{pid: uint32(os.Getpid()), start: parentStart, fd: strconv.Itoa(fd)}
	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	child := exec.Command("sleep", "20")
	child.ExtraFiles = []*os.File{f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	pid := uint32(child.Process.Pid)
	start, err := processStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	var dir unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/fd", pid), &dir); err != nil {
		t.Fatal(err)
	}
	key := descriptorBatchKey{pid: pid, uid: row.uid, start: start, directory: dir.Ino, limit: 64, cacheAll: true}
	reader := newTestOwners(t)
	// Read the real child descriptors now; the test later delays publication
	// of these exact positive hints, as a descheduled worker can do.
	result := reader.readDescriptorBatch(&descriptorBatch{key: key, deadline: time.Now().Add(time.Second)})
	b := reader.indexed(row.inode).first
	if b.pid != pid || b.start != start || len(result.sockets) == 0 {
		t.Fatalf("child did not hold the real inherited socket: %+v, %v", b, result.err)
	}
	return row, a, b, key, result
}

func TestOtherPIDNotificationCannotHideAConflictingHolder(t *testing.T) {
	row, a, b, key, result := sharedBatchSocket(t)
	// The UID fallback has one preferred candidate: the child whose batch
	// is pending. Its parent's notification must not end that child's scan.
	row.cgroup = 0
	o := newTestOwners(t)
	o.rememberPID(row.uid, b.pid)
	pending := &descriptorBatch{key: key, done: make(chan struct{})}
	o.batches.jobs = make(chan *descriptorBatch, 128)
	o.batches.available = make(chan struct{})
	o.batches.live = map[descriptorBatchKey]*descriptorBatch{key: pending}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := o.holders(ctx, row); done <- err }()
	until := time.Now().Add(time.Second)
	for o.batches.shared.Load() == 0 && time.Now().Before(until) {
		runtime.Gosched()
	}
	if o.batches.shared.Load() == 0 {
		t.Fatal("fixture never waited for the child's descriptor batch")
	}
	o.publish(map[uint32]holder{row.inode: a})
	select {
	case err := <-done:
		t.Fatalf("first PID's publication ended the second PID's unfinished search: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	pending.result = result
	o.publish(map[uint32]holder{row.inode: b})
	o.batches.mu.Lock()
	delete(o.batches.live, key)
	close(pending.done)
	o.batches.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, platform.ErrAmbiguous) {
			t.Fatalf("two different real executables sharing a socket: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup did not finish after both real holders were published")
	}
}

func TestFullBatchQueueCannotChooseOneConflictingHolder(t *testing.T) {
	row, a, b, _, _ := sharedBatchSocket(t)
	o := newTestOwners(t)
	warm, finishWarm := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishWarm()
	if err := o.Warm(warm); err != nil {
		t.Fatal(err)
	}
	if row.cgroup == 0 {
		t.Fatal("fixture needs the real socket cgroup to search both holders")
	}
	o.rememberPID(row.uid, b.pid)
	o.publish(map[uint32]holder{row.inode: a})
	// Hold a genuinely full queue with no consumer progress during the call.
	// Identities still come from two live processes and their real shared FD.
	o.batches.jobs = make(chan *descriptorBatch, 1)
	o.batches.jobs <- &descriptorBatch{done: make(chan struct{})}
	o.batches.available = make(chan struct{})
	o.batches.live = make(map[descriptorBatchKey]*descriptorBatch)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	owner, err := o.holders(ctx, row)
	if o.batches.full.Load() == 0 || len(o.batches.jobs) != cap(o.batches.jobs) {
		t.Fatal("fixture did not keep the descriptor queue full")
	}
	<-o.batches.jobs
	if !errors.Is(err, context.DeadlineExceeded) || owner.AppID != "" {
		t.Fatalf("unfinished conflicting search chose a partial owner: %+v %v", owner, err)
	}
	control := newTestOwners(t)
	control.rememberPID(row.uid, b.pid)
	control.publish(map[uint32]holder{row.inode: a})
	ctx2, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := control.holders(ctx2, row); !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("unblocked real shared-socket control: %v", err)
	}
}
