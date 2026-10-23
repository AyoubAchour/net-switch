//go:build windows

package winchild

import (
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The child is still suspended: its runtime cannot allocate/reuse a decoy's
// numeric value. Inspect the actual inherited handle table, not its own claim.
func inheritedHandles(t *testing.T, pid uint32) []windows.Handle {
	t.Helper()
	var words []uint64
	for size := uint32(1 << 20); ; size *= 2 {
		if size > 128<<20 {
			t.Fatal("system handle snapshot exceeded test bound")
		}
		words = make([]uint64, size/8)
		var used uint32
		err := windows.NtQuerySystemInformation(windows.SystemExtendedHandleInformation, unsafe.Pointer(&words[0]), size, &used)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			t.Fatal(err)
		}
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	count := binary.LittleEndian.Uint64(b[:8])
	if count > uint64((len(b)-16)/40) {
		t.Fatal("invalid handle snapshot")
	}
	var handles []windows.Handle
	for i := uint64(0); i < count; i++ {
		row := b[16+i*40 : 16+(i+1)*40]
		if binary.LittleEndian.Uint64(row[8:16]) == uint64(pid) && binary.LittleEndian.Uint32(row[32:36])&2 != 0 {
			handles = append(handles, windows.Handle(binary.LittleEndian.Uint64(row[16:24])))
		}
	}
	return handles
}

func TestHostedHandleListExcludesInheritableDecoy(t *testing.T) {
	requireHosted(t)
	decoy, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(decoy)
	if err := windows.SetHandleInformation(decoy, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		t.Fatal(err)
	}
	original := restrictHandles
	defer func() { restrictHandles = original }()
	for _, restricted := range []bool{false, true} {
		restrictHandles = original
		if !restricted {
			restrictHandles = func(*windows.ProcThreadAttributeListContainer, []windows.Handle) error { return nil }
		}
		p := startFixture(t, true, "hold")
		handles := inheritedHandles(t, p.Identity.PID)
		leaked := false
		for _, handle := range handles {
			leaked = leaked || handle == decoy
			if restricted {
				var copy windows.Handle
				if err := windows.DuplicateHandle(p.process.Handle("inheritance proof source"), handle, windows.CurrentProcess(), &copy, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
					t.Fatal(err)
				}
				kind, err := windows.GetFileType(copy)
				closeErr := windows.CloseHandle(copy)
				if err != nil || closeErr != nil || kind != windows.FILE_TYPE_PIPE {
					t.Fatal("inherited a non-pipe", kind, err, closeErr)
				}
			}
		}
		if restricted && (leaked || len(handles) != 3) {
			t.Fatal("handle whitelist failed", handles, decoy)
		}
		if !restricted && (!leaked || len(handles) < 4) {
			t.Fatal("negative control did not inherit decoy", handles, decoy)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("CHILD_INHERITANCE restricted=%t inherited=%d decoy_inherited=%t", restricted, len(handles), leaked)
	}
}
