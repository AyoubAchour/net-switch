//go:build windows

package wintun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const sectionRingBytes = MinCapacity + ringHeader + ringSlack
const sectionMetadata = (sectionRingBytes*2 + 4095) &^ 4095
const sectionProbeBytes = sectionMetadata + 4096
const sectionParentMark uint64 = 0x4e5353454354494f
const sectionChildMark uint64 = 0x4e534348494c4421
const sectionMappedMemory = 0x40000 // MEM_MAPPED, MEMORY_BASIC_INFORMATION.Type.

type sectionProbeConfig struct {
	GUID, Instance             string
	Mapping, Read, Write, Stop uint64
	ParentAddress              uint64
}

type sectionProbeReady struct {
	PID                                 int
	Address                             uint64
	MemoryType                          uint32
	Handles                             uint32
	PrivateBytes, HeapBytes, StackBytes uint64
}

func sectionProbeView(address uintptr) []byte {
	// The view is native memory, never a converted Go-heap pointer.
	pointer := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	return unsafe.Slice((*byte)(pointer), sectionProbeBytes)
}

// This child deliberately has NO device-handle Close path. The driver or
// process teardown disposes of the registration. It never performs packet I/O.
func TestWintunSectionProbeChild(t *testing.T) {
	raw := os.Getenv("NETSWITCH_SECTION_PROBE_CHILD")
	if raw == "" {
		t.Skip("section probe child only")
	}
	requireRunner(t)
	var config sectionProbeConfig
	must(t, json.Unmarshal([]byte(raw), &config))
	guid, err := windows.GUIDFromString(config.GUID)
	must(t, err)
	path, instance, err := deviceForGUID(guid)
	must(t, err)
	if !strings.EqualFold(instance, config.Instance) {
		t.Fatal("helper found a different device instance")
	}
	// Occupy the parent's address if available; an occupied address is already
	// sufficient. The mapped view must actually end up at a different address.
	_, _ = windows.VirtualAlloc(uintptr(config.ParentAddress), sectionProbeBytes,
		windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	mapping := winhandle.Open(windows.Handle(config.Mapping), "section helper inherited mapping")
	view, err := windows.MapViewOfFile(mapping.Handle("section helper map"), windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, sectionProbeBytes)
	must(t, err)
	if view == uintptr(config.ParentAddress) {
		t.Fatal("fixture failed to obtain a different helper view address")
	}
	var memory windows.MemoryBasicInformation
	must(t, windows.VirtualQuery(view, &memory, unsafe.Sizeof(memory)))
	if memory.Type != sectionMappedMemory {
		t.Fatalf("helper view is not shared mapped memory: %#x", memory.Type)
	}
	data := sectionProbeView(view)
	if atomic.LoadUint64((*uint64)(unsafe.Pointer(&data[sectionMetadata]))) != sectionParentMark {
		t.Fatal("helper could not see the parent's section write")
	}
	read := winhandle.Open(windows.Handle(config.Read), "section helper inherited read event")
	write := winhandle.Open(windows.Handle(config.Write), "section helper inherited write event")
	stop := winhandle.Open(windows.Handle(config.Stop), "section helper inherited stop event")
	name, err := windows.UTF16PtrFromString(path)
	must(t, err)
	device, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	must(t, err)
	owner := winhandle.OpenDriverHandle(device, "section helper process-owned registration")
	desc := registration{
		Send:    ringRegistration{sectionRingBytes, &data[0], read.Handle("section helper registration read")},
		Receive: ringRegistration{sectionRingBytes, &data[sectionRingBytes], write.Handle("section helper registration write")},
	}
	var returned uint32
	must(t, windows.DeviceIoControl(owner.Handle("section helper registration"), registerRingsIOCTL,
		(*byte)(unsafe.Pointer(&desc)), uint32(unsafe.Sizeof(desc)), nil, 0, &returned, nil))
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&data[sectionMetadata+8])), sectionChildMark)
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	handles, private := processUsage(t)
	ready, err := json.Marshal(sectionProbeReady{PID: os.Getpid(), Address: uint64(view), MemoryType: memory.Type,
		Handles: handles, PrivateBytes: private, HeapBytes: stats.HeapAlloc, StackBytes: stats.StackInuse})
	must(t, err)
	fmt.Printf("SECTION_HELPER_READY %s\n", ready)
	result, err := windows.WaitForSingleObject(stop.Handle("section helper lifecycle wait"), windows.INFINITE)
	must(t, err)
	if result != windows.WAIT_OBJECT_0 {
		t.Fatalf("unexpected helper lifecycle wait: %d", result)
	}
	// No Go cleanup can touch a numeric device value the driver may have
	// recycled. Process teardown also releases the helper's mapped view.
	os.Exit(0)
}

type sectionProbeIO struct{ rings *rings }

func (s *sectionProbeIO) ReadBatch(ctx context.Context, buffers [][]byte, sizes []int) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := s.rings.read(buffers, sizes)
		if n != 0 || err != nil {
			return n, err
		}
		_, err = windows.WaitForSingleObject(s.rings.readHandle(), 20)
		if err != nil {
			return 0, err
		}
	}
}
func (s *sectionProbeIO) WriteBatch(packets [][]byte) (int, error) {
	n, dropped, err := s.rings.write(packets)
	if dropped != 0 {
		err = errors.Join(err, fmt.Errorf("section ring dropped %d packets", dropped))
	}
	return n, err
}
func (*sectionProbeIO) Close() error { return nil } // helper lifecycle owns retirement

func TestWintunSharedSectionOwner(t *testing.T) {
	requireRunner(t)
	adapter := newAdapter(t, MinCapacity)
	for _, mode := range []string{"exit", "terminate", "adapter-remove"} {
		t.Run(mode, func(t *testing.T) { runSectionOwnerProbe(t, adapter, mode) })
		if t.Failed() {
			return
		}
	}
}

func runSectionOwnerProbe(t *testing.T, adapter *Adapter, mode string) {
	t.Helper()
	h, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, 0, sectionProbeBytes, nil)
	must(t, err)
	mapping := winhandle.Open(h, "section probe parent mapping")
	defer mapping.HandleClose("section probe parent mapping close")
	view, err := windows.MapViewOfFile(mapping.Handle("section probe parent map"), windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, sectionProbeBytes)
	must(t, err)
	defer windows.UnmapViewOfFile(view) // deferred after child join is installed below
	var memory windows.MemoryBasicInformation
	must(t, windows.VirtualQuery(view, &memory, unsafe.Sizeof(memory)))
	if memory.Type != sectionMappedMemory {
		t.Fatal("parent view is not section-backed")
	}
	data := sectionProbeView(view)
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&data[sectionMetadata])), sectionParentMark)
	var events [3]winhandle.Owner
	for i := range events {
		h, err := windows.CreateEvent(nil, 0, 0, nil)
		must(t, err)
		events[i] = winhandle.Open(h, fmt.Sprintf("section probe parent event %d", i))
		defer events[i].HandleClose("section probe parent event close")
	}
	config := sectionProbeConfig{GUID: adapter.config.GUID, Instance: adapter.instanceID,
		Mapping: uint64(mapping.Handle("section inheritance")),
		Read:    uint64(events[0].Handle("section read inheritance")), Write: uint64(events[1].Handle("section write inheritance")),
		Stop: uint64(events[2].Handle("section stop inheritance")), ParentAddress: uint64(view)}
	inherit := []syscall.Handle{syscall.Handle(config.Mapping), syscall.Handle(config.Read), syscall.Handle(config.Write), syscall.Handle(config.Stop)}
	for _, handle := range inherit {
		must(t, windows.SetHandleInformation(windows.Handle(handle), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT))
	}
	self, err := os.Executable()
	must(t, err)
	encoded, err := json.Marshal(config)
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestWintunSectionProbeChild$", "-test.v")
	cmd.Env = append(os.Environ(), "NETSWITCH_SECTION_PROBE_CHILD="+string(encoded))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, AdditionalInheritedHandles: inherit}
	output, err := cmd.StdoutPipe()
	must(t, err)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())
	ready := make(chan sectionProbeReady, 1)
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "SECTION_HELPER_READY ") {
				var value sectionProbeReady
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "SECTION_HELPER_READY ")), &value) == nil {
					ready <- value
				}
			} else {
				t.Logf("section helper: %s", line)
			}
		}
	}()
	done := make(chan error, 1)
	go func() { <-scanned; done <- cmd.Wait() }()
	joined := false
	defer func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-done // process termination precedes every view/event release
		}
	}()
	for _, handle := range inherit {
		must(t, windows.SetHandleInformation(windows.Handle(handle), windows.HANDLE_FLAG_INHERIT, 0))
	}
	var child sectionProbeReady
	select {
	case child = <-ready:
	case err := <-done:
		joined = true
		t.Fatalf("section helper exited before registration: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("section helper registration timed out")
	}
	if child.PID != cmd.Process.Pid || child.Address == uint64(view) ||
		atomic.LoadUint64((*uint64)(unsafe.Pointer(&data[sectionMetadata+8]))) != sectionChildMark {
		t.Fatal("helper registration did not prove separate, coherent section views")
	}
	r := &rings{send: ring{data[:sectionRingBytes], MinCapacity},
		receive:   ring{data[sectionRingBytes : sectionRingBytes*2], MinCapacity},
		readEvent: windows.Handle(config.Read), writeEvent: windows.Handle(config.Write),
		readOwner: events[0], writeOwner: events[1]}
	f := &fixture{a: adapter, io: &sectionProbeIO{r}}
	f.startEcho(t)
	defer f.stopEcho()
	client := udpSocket(t)
	defer client.Close()
	var reply [2048]byte
	warmed := false
	for range 30 {
		client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := client.Write([]byte("section warmup")); err == nil {
			n, err := client.Read(reply[:])
			if err == nil && string(reply[:n]) == "section warmup" {
				warmed = true
				break
			}
		}
	}
	if !warmed {
		t.Fatal("shared-section adapter never became ready")
	}
	for round := range 64 {
		payload := bytes.Repeat([]byte{byte(round), 0x17, 0x92}, 200)
		must(t, client.SetDeadline(time.Now().Add(time.Second)))
		_, err := client.Write(payload)
		must(t, err)
		n, err := client.Read(reply[:])
		must(t, err)
		if !bytes.Equal(payload, reply[:n]) {
			t.Fatal("shared-section packet corruption")
		}
	}
	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("shared-section packet path failed: %v", f.fault())
	}
	removalObserved := false
	guardsChecked := 0
	if mode == "adapter-remove" {
		type guard struct{ event, witness winhandle.Owner }
		var guards []guard
		for range 32 {
			handle, err := windows.CreateEvent(nil, 0, 0, nil)
			must(t, err)
			event := winhandle.Open(handle, "section removal parent guard")
			var copy windows.Handle
			if err := windows.DuplicateHandle(windows.CurrentProcess(), handle, windows.CurrentProcess(), &copy, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
				event.HandleClose("section guard witness failure close")
				t.Fatal(err)
			}
			witness := winhandle.Open(copy, "section removal parent witness")
			guards = append(guards, guard{event, witness})
			defer func() {
				if sameObject(event.Handle("section guard cleanup identity"), witness.Handle("section witness cleanup identity")) {
					event.HandleClose("section parent guard close")
				}
				witness.HandleClose("section parent witness close")
			}()
		}
		must(t, adapter.Close())
		assertPnPAbsent(t, adapter.instanceID)
		deadline := time.Now().Add(5 * time.Second)
		for r.send.load(4) != ^uint32(0) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		removalObserved = r.send.load(4) == ^uint32(0)
		if !removalObserved {
			t.Fatal("real adapter removal did not release the helper's registration")
		}
		for _, guard := range guards {
			event := guard.event.Handle("section removal guard identity")
			if !sameObject(event, guard.witness.Handle("section removal witness identity")) {
				t.Fatal("adapter removal closed or replaced an unrelated parent handle")
			}
			must(t, windows.SetEvent(event))
			guardsChecked++
		}
		select {
		case err := <-done:
			joined = true
			t.Fatalf("helper exit, not adapter removal, supplied the marker: %v", err)
		default:
		}
	}
	started := ticks()
	if mode == "terminate" {
		must(t, cmd.Process.Kill())
	} else {
		must(t, windows.SetEvent(events[2].Handle("section helper stop request")))
	}
	err = <-done
	joined = true
	if mode == "terminate" {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatalf("forced helper termination was not observed: %v", err)
		}
	} else {
		must(t, err)
	}
	if r.send.load(4) != ^uint32(0) || r.receive.load(0) != ^uint32(0) {
		t.Fatal("helper process finished without both driver-release markers")
	}
	report(t, map[string]any{"test": "shared_section_owner", "mode": mode,
		"parent_address": uint64(view), "helper_address": child.Address,
		"parent_memory_type": memory.Type, "helper_memory_type": child.MemoryType,
		"helper_handles": child.Handles, "helper_private_bytes": child.PrivateBytes,
		"helper_heap_bytes": child.HeapBytes, "helper_stack_bytes": child.StackBytes,
		"section_backing_bytes": sectionProbeBytes,
		"coherent_views":        true, "round_trips_no_retries": 64, "helper_packet_work": false,
		"helper_exited": true, "driver_markers_after_exit": true, "exit_ms": float64(elapsed(started)) / float64(time.Millisecond),
		"external_removal_before_helper_exit":       removalObserved,
		"unrelated_parent_objects_preserved":        guardsChecked,
		"query_remove_and_job_crash_not_yet_tested": true})
}
