//go:build linux

package linux

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func TestDuplicateDescriptorsDoNotConsumeDistinctHolderSlots(t *testing.T) {
	o := newTestOwners(t)
	row, parent, child, _, _ := sharedBatchSocket(t)
	base, err := strconv.Atoi(parent.fd)
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		fd, err := unix.Dup(base)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		parent.fd = strconv.Itoa(fd)
		o.publish(map[uint32]holder{row.inode: parent})
	}
	if got := o.indexed(row.inode); got.count() != 1 || got.first != parent {
		t.Fatalf("one process's duplicate descriptors consumed holder slots: %+v", got)
	}
	o.publish(map[uint32]holder{row.inode: child})
	got := o.indexed(row.inode)
	if got.count() != 2 || got.more[0] != child {
		t.Fatalf("duplicate descriptors hid the real second process: %+v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if owner, err := o.holders(ctx, row); !errors.Is(err, platform.ErrAmbiguous) || owner.AppID != "" {
		t.Fatalf("real shared socket lost its conflicting identity: %+v %v", owner, err)
	}
}

func TestClosedRepresentativeDoesNotHideOtherLiveDuplicates(t *testing.T) {
	o := newTestOwners(t)
	row, parent, child, _, _ := sharedBatchSocket(t)
	base, err := strconv.Atoi(parent.fd)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(base)
	if err != nil {
		t.Fatal(err)
	}
	closeFD := sync.OnceFunc(func() { unix.Close(fd) })
	t.Cleanup(closeFD)
	parent.fd = strconv.Itoa(fd)
	o.publish(map[uint32]holder{row.inode: parent})
	o.publish(map[uint32]holder{row.inode: child})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := o.holders(ctx, row); !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("fixture must first observe both live process identities: %v", err)
	}
	closeFD()
	if inode, ok := socketInodeAt(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(base)); !ok || inode != row.inode {
		t.Fatal("fixture lost the remaining parent descriptor")
	}
	if owner, err := o.holders(ctx, row); !errors.Is(err, platform.ErrAmbiguous) || owner.AppID != "" {
		t.Fatalf("closing one duplicate hid a still-live conflicting process: %+v %v", owner, err)
	}
}

func TestHolderRepresentativeUpdatesPreservePublishedSnapshots(t *testing.T) {
	o := newTestOwners(t)
	const inode = uint32(43)
	first := holder{pid: 100, start: 1, fd: "3"}
	second := holder{pid: 101, start: 2, fd: "4"}
	o.publish(map[uint32]holder{inode: first})
	o.publish(map[uint32]holder{inode: second})
	before := o.indexed(inode)
	first.fd, second.fd = "13", "14"
	o.publish(map[uint32]holder{inode: first})
	o.publish(map[uint32]holder{inode: second})
	after := o.indexed(inode)
	if before.first.fd != "3" || len(before.more) != 1 || before.more[0].fd != "4" {
		t.Fatalf("updating a representative mutated an unlocked reader's snapshot: %+v", before)
	}
	if after.count() != 2 || after.first != first || after.more[0] != second {
		t.Fatalf("live representative was not replaced within its process slot: %+v", after)
	}
	// A new process incarnation must still pass its own identity validation.
	// Do not conflate its hint with an earlier holder that used the same PID.
	second.start++
	o.publish(map[uint32]holder{inode: second})
	if o.indexed(inode).count() != 3 {
		t.Fatal("different process incarnations were collapsed")
	}
	notice := o.subscribe(inode)
	defer o.unsubscribe(inode, notice)
	o.publish(map[uint32]holder{inode: second})
	select {
	case <-notice.ready:
	default:
		t.Fatal("an unchanged but freshly observed descriptor did not notify its waiter")
	}
}
