//go:build windows && netswitch_handlecheck

package winengine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"github.com/AyoubAchour/net-switch/internal/winwait"
	"golang.org/x/sys/windows"
)

type heapProfileInfo struct {
	Nonce, Instance, Event, Architecture string
	PID                                  int
	Instrumented                         bool
}

type heapProfileRequest struct {
	Sequence                   uint64
	Nonce, RequestNonce, Label string
}

type heapProfileResult struct {
	heapProfileInfo
	Request                             heapProfileRequest
	CapturedAt                          time.Time
	HeapAlloc, StackInUse, ManagedBytes uint64
	ForcedGCBefore, ForcedGCAfter       uint32
	GCCPUSeconds, TotalCPUSeconds       float64
	MemoryLimit, GOGC                   uint64
	GOMAXPROCS, Goroutines              int
	Process                             ProcessMemory
	ProcessError                        string `json:",omitempty"`
	KernelSocketBytes                   *uint64
	KernelSocketMemoryNote              string
	Build                               []debug.BuildSetting
	Error                               string `json:",omitempty"`
}

type heapProfile struct {
	info          heapProfileInfo
	dir           *winhandle.File
	request, stop winhandle.Owner
	done          chan struct{}
	once          sync.Once
	err           error
	// waits is run's native wait array, kept in this heap object so no
	// stack copy can move it under the kernel.
	waits [2]windows.Handle
}

func validProfileNonce(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 16 && len(value) == 32
}

func createHeapEvent(name string) (winhandle.Owner, error) {
	sa, err := security("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return winhandle.Owner{}, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return winhandle.Owner{}, err
	}
	// Read ERROR_ALREADY_EXISTS even when CreateEvent succeeds: this test
	// endpoint must be freshly created with our ACL, never an adopted object.
	value, _, callErr := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateEventW").Call(
		uintptr(unsafe.Pointer(sa)), 0, 0, uintptr(unsafe.Pointer(p)))
	if value == 0 {
		return winhandle.Owner{}, fmt.Errorf("create private heap event: %v", callErr)
	}
	owner := winhandle.Open(windows.Handle(value), "heap request event open")
	if errors.Is(callErr, windows.ERROR_ALREADY_EXISTS) {
		owner.HandleClose("heap event collision close")
		return winhandle.Owner{}, errors.New("heap request event already exists")
	}
	return owner, nil
}

func startHeapProfile(instance string, standalone bool) (func() error, error) {
	dir, nonce := os.Getenv("NETSWITCH_ENGINE_HEAP_DIR"), os.Getenv("NETSWITCH_ENGINE_HEAP_NONCE")
	if dir == "" && nonce == "" {
		return func() error { return nil }, nil
	}
	if !standalone || !hostedTraceEnabled() || !validProfileNonce(nonce) || !filepath.IsAbs(dir) {
		return nil, errors.New("heap profiling requires hosted standalone mode, an absolute private directory and a fresh nonce")
	}
	p, err := openHeapProfile(dir, nonce, instance)
	if err != nil {
		return nil, err
	}
	return p.close, nil
}

func openHeapProfile(dir, nonce, instance string) (*heapProfile, error) {
	guard, err := StateDirectory(dir)
	if err != nil {
		return nil, err
	}
	info := heapProfileInfo{Nonce: nonce, Instance: instance, PID: os.Getpid(), Architecture: runtime.GOARCH,
		Event: `Local\NetSwitchEngineHeap-` + nonce, Instrumented: true}
	request, err := createHeapEvent(info.Event)
	if err != nil {
		guard.Close()
		return nil, err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		request.HandleClose("heap setup failure request close")
		guard.Close()
		return nil, err
	}
	p := &heapProfile{info: info, dir: guard, request: request,
		stop: winhandle.Open(stop, "heap stop event open"), done: make(chan struct{})}
	if err := publishHeapJSON(filepath.Join(dir, "ready.json"), info); err != nil {
		request.HandleClose("heap metadata failure request close")
		p.stop.HandleClose("heap metadata failure stop close")
		guard.Close()
		return nil, err
	}
	go p.run()
	return p, nil
}

func publishHeapJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".heap-capture-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	_, err = temp.Write(b)
	if err == nil {
		err = temp.Sync()
	}
	err = errors.Join(err, temp.Close())
	if err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// No replacement: an existing sequence is stale or a duplicate request.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func readPublishedHeapJSON(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Rename publishes the new name before MoveFileEx releases its DELETE
	// handle. Share that access so a complete, immutable capture is readable
	// during this window. os.ReadFile omits FILE_SHARE_DELETE on Windows.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open heap capture", Path: path, Err: err}
	}
	file := winhandle.NewFile(winhandle.Open(handle, "heap published file open"), path)
	data, err := io.ReadAll(file)
	return data, errors.Join(err, file.Close())
}

func (p *heapProfile) run() {
	defer close(p.done)
	var sequence uint64
	for {
		p.waits = [2]windows.Handle{p.stop.Handle("heap stop wait"), p.request.Handle("heap request wait")}
		result, err := winwait.WaitForMultipleObjects(p.waits[:], false, windows.INFINITE)
		if err != nil {
			p.err = fmt.Errorf("heap capture wait (stop %#x, request %#x): %w", p.waits[0], p.waits[1], err)
			return
		}
		if result == windows.WAIT_OBJECT_0 {
			return
		}
		if result != windows.WAIT_OBJECT_0+1 {
			p.err = fmt.Errorf("unexpected heap event wait result %d", result)
			return
		}
		next := sequence + 1
		var request heapProfileRequest
		b, err := readPublishedHeapJSON(filepath.Join(p.dir.Name(), fmt.Sprintf("request-%06d.json", next)))
		if err != nil || len(b) > 4096 || json.Unmarshal(b, &request) != nil ||
			request.Sequence != next || request.Nonce != p.info.Nonce || !validProfileNonce(request.RequestNonce) {
			log.Printf("heap capture request %d rejected: invalid/missing request (%v)", next, err)
			continue
		}
		sequence = next
		snapshot := p.capture(request)
		if err := publishHeapJSON(filepath.Join(p.dir.Name(), fmt.Sprintf("memory-%06d.json", next)), snapshot); err != nil {
			log.Printf("heap capture %d could not be published: %v", next, err)
		}
	}
}

func (p *heapProfile) capture(request heapProfileRequest) heapProfileResult {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	runtime.GC()
	runtime.ReadMemStats(&after) // Keep this immediately after GC, before serialization or profiles.
	result := heapProfileResult{heapProfileInfo: p.info, Request: request, CapturedAt: time.Now(),
		HeapAlloc: after.HeapAlloc, StackInUse: after.StackInuse, ManagedBytes: after.Sys - after.HeapReleased,
		ForcedGCBefore: before.NumForcedGC, ForcedGCAfter: after.NumForcedGC,
		GOMAXPROCS: runtime.GOMAXPROCS(0), Goroutines: runtime.NumGoroutine(),
		KernelSocketMemoryNote: "unknown: Windows process/system pool totals do not isolate socket memory"}
	samples := []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/gc/gomemlimit:bytes"}, {Name: "/gc/gogc:percent"}}
	metrics.Read(samples)
	result.GCCPUSeconds, result.TotalCPUSeconds = samples[0].Value.Float64(), samples[1].Value.Float64()
	result.MemoryLimit, result.GOGC = samples[2].Value.Uint64(), samples[3].Value.Uint64()
	var err error
	result.Process, err = processMemory()
	if err != nil {
		result.ProcessError = err.Error()
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		result.Build = build.Settings
	}
	return result
}

func (p *heapProfile) close() error {
	p.once.Do(func() {
		err := windows.SetEvent(p.stop.Handle("heap profiler stop"))
		<-p.done
		p.err = errors.Join(p.err, err, p.request.HandleClose("heap request event close"),
			p.stop.HandleClose("heap stop event close"), p.dir.Close())
	})
	return p.err
}

func requestHeapCapture(dir, nonce, instance, requestNonce, label string, pid int, sequence uint64) (heapProfileResult, error) {
	var result heapProfileResult
	if !hostedTraceEnabled() || !Elevated() || !validProfileNonce(nonce) || !validProfileNonce(requestNonce) || sequence == 0 {
		return result, errors.New("heap capture requires an elevated hosted harness and fresh request identity")
	}
	var info heapProfileInfo
	b, err := readPublishedHeapJSON(filepath.Join(dir, "ready.json"))
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return result, err
	}
	if !info.Instrumented || info.PID != pid || info.Nonce != nonce || info.Instance != instance ||
		info.Event != `Local\NetSwitchEngineHeap-`+nonce {
		return result, errors.New("heap capture endpoint does not match this engine instance")
	}
	request := heapProfileRequest{Sequence: sequence, Nonce: nonce, RequestNonce: requestNonce, Label: label}
	if err := publishHeapJSON(filepath.Join(dir, fmt.Sprintf("request-%06d.json", sequence)), request); err != nil {
		return result, err
	}
	name, _ := windows.UTF16PtrFromString(info.Event)
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return result, err
	}
	event := winhandle.Open(h, "heap harness event open")
	defer event.HandleClose("heap harness event close")
	if err := windows.SetEvent(event.Handle("heap harness request signal")); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output := filepath.Join(dir, fmt.Sprintf("memory-%06d.json", sequence))
	for {
		b, err := readPublishedHeapJSON(output)
		if err == nil {
			if err := json.Unmarshal(b, &result); err != nil {
				return result, err
			}
			if result.Request != request || result.PID != pid || result.Instance != instance || result.Nonce != nonce ||
				!result.Instrumented || result.ForcedGCAfter <= result.ForcedGCBefore {
				return result, errors.New("heap capture completion is stale or did not force GC")
			}
			return result, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		if err := winclock.System.Wait(ctx, 10*time.Millisecond); err != nil {
			return result, err
		}
	}
}

func CaptureHeapCommand(args []string) error {
	flags := flag.NewFlagSet("heap-capture", flag.ContinueOnError)
	dir := flags.String("profile-dir", "", "private capture directory")
	nonce := flags.String("nonce", "", "engine profile nonce")
	instance := flags.String("instance", "", "engine instance")
	request := flags.String("request-nonce", "", "fresh request nonce")
	label := flags.String("label", "", "capture phase")
	pid := flags.Int("pid", 0, "engine process")
	sequence := flags.Uint64("sequence", 0, "capture sequence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected heap capture arguments")
	}
	result, err := requestHeapCapture(*dir, *nonce, *instance, *request, *label, *pid, *sequence)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
