//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

// These tests use the real Engine pumps, Stop and journal, but no adapter,
// routes, sockets, WFP or services. The TUN owns only an anonymous event; an
// independent duplicate queries the kernel object's handle count after Stop.
type lossTestTun struct {
	*testfake.Tun
	fault            chan error
	owner            winhandle.Owner
	closeOnce        sync.Once
	closeErr         error
	injectedCloseErr error
}

func (t *lossTestTun) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	select {
	case err := <-t.fault:
		return 0, err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (t *lossTestTun) BeginClose() { t.Tun.Close() }
func (t *lossTestTun) Close() error {
	t.closeOnce.Do(func() {
		t.BeginClose()
		t.closeErr = errors.Join(t.owner.HandleClose("adapter-loss test TUN event close"), t.injectedCloseErr)
	})
	return t.closeErr
}

func newLossTestTun(t *testing.T) (*lossTestTun, winhandle.Owner) {
	t.Helper()
	h, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	tun := &lossTestTun{Tun: testfake.NewTun(), fault: make(chan error, 1), owner: winhandle.Open(h, "adapter-loss test TUN event")}
	t.Cleanup(func() { tun.Close() })
	var witness windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &witness, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	w := winhandle.Open(witness, "adapter-loss test witness")
	t.Cleanup(func() { w.HandleClose("adapter-loss test witness close") })
	return tun, w
}

func lossObjectHandles(t *testing.T, witness winhandle.Owner) uint32 {
	t.Helper()
	// PUBLIC_OBJECT_BASIC_INFORMATION, documented by Microsoft for
	// NtQueryObject(ObjectBasicInformation). A word array preserves alignment.
	var info [7]uint64
	var size uint32
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject").Call(
		uintptr(witness.Handle("adapter-loss test object handle count")), 0,
		uintptr(unsafe.Pointer(&info[0])), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&size)))
	if uint32(status) != 0 || size < 16 {
		t.Fatalf("NtQueryObject status=%#x size=%d", status, size)
	}
	return uint32(info[1]) // DWORD HandleCount at byte offset 8
}

type lossJournalStore struct{ records []journal.Record }

func (s *lossJournalStore) Records() ([]journal.Record, error) {
	return append([]journal.Record(nil), s.records...), nil
}
func (s *lossJournalStore) Append(r journal.Record) error {
	s.records = append(s.records, r)
	return nil
}

type lossTestRoutes struct {
	session *journal.Session
	cleaned atomic.Bool
}

func (*lossTestRoutes) Prepare(context.Context, []platform.Line) error { return nil }
func (r *lossTestRoutes) Capture(ctx context.Context) error {
	return r.session.Create(ctx, "test", journal.Fingerprint{"name": "capture"})
}
func (r *lossTestRoutes) Cleanup(ctx context.Context) error {
	err := r.session.Cleanup(ctx)
	r.cleaned.Store(err == nil)
	return err
}

func TestAdapterLossContractCleansJournalAndNativeHandleBeforeReceipt(t *testing.T) {
	for _, scenario := range []struct {
		name                             string
		cause                            error
		failJournal, failClose, failExit bool
	}{
		{"removed", wintun.ErrAdapterRemoved, false, false, false},
		{"wrapped removal", fmt.Errorf("session: %w", wintun.ErrAdapterRemoved), false, false, false},
		{"journal failure", wintun.ErrAdapterRemoved, true, false, false},
		{"close failure", wintun.ErrAdapterRemoved, false, true, false},
		{"runtime resource close failure", wintun.ErrAdapterRemoved, false, false, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			tun, witness := newLossTestTun(t)
			if scenario.failClose {
				tun.injectedCloseErr = errors.New("test TUN close failure")
			}
			if count := lossObjectHandles(t, witness); count != 2 {
				t.Fatalf("missing live TUN handle precondition: %d", count)
			}
			objects := &checkpointObjects{live: map[string]journal.Fingerprint{}}
			j := &journal.Journal{Store: &lossJournalStore{}, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"test": objects}}
			session, err := j.Open(context.Background(), "test-boot", "test-engine")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			routes := &lossTestRoutes{session: session}
			e := engine.New(context.Background(), engine.Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil },
				Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
			defer e.Stop(context.Background())
			loss := newAdapterLoss()
			e.OnTunError = loss.handle
			var fatals atomic.Int32
			e.OnFatal = func(error) { fatals.Add(1) }
			var exitErr error
			if scenario.failExit {
				exitErr = errors.New("runtime lifetime resource close failure")
			}
			runtime := &Runtime{Engine: e,
				routes: &Routes{Instance: "test-engine", timings: &phaseTimings{values: map[string]phaseTiming{}}}}
			s := protocol.New(runtime, e.Table, nil)
			server, controller := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer controller.Close()
			controller.SetDeadline(time.Now().Add(8 * time.Second))
			served := make(chan error, 1)
			go func() { served <- s.Serve(ctx, server) }()
			enc, dec := json.NewEncoder(controller), json.NewDecoder(controller)
			call := func(r protocol.Request) protocol.Reply {
				t.Helper()
				if err := enc.Encode(r); err != nil {
					t.Fatal(err)
				}
				var out protocol.Reply
				if err := dec.Decode(&out); err != nil {
					t.Fatal(err)
				}
				if out.Error != "" {
					t.Fatal(out.Error)
				}
				return out
			}
			attached := call(protocol.Request{ID: "attach", Method: "attach", Instance: s.Instance})
			epoch := uint64(attached.Result.(map[string]any)["epoch"].(float64))
			config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
			v := policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}
			call(protocol.Request{ID: "start", Method: "start", Instance: s.Instance, Epoch: epoch, Revision: &v})
			if len(objects.live) != 1 || e.Table.Applied() == nil {
				t.Fatal("capture precondition missing")
			}
			if scenario.failJournal {
				objects.fail = "capture"
			}
			var pipeClosed, joined, released atomic.Bool
			stopped := make(chan error, 1)
			go func() {
				stopped <- serveUntilStopped(context.Background(), shutdownTail{
					runtime: runtime, server: s, loss: loss, fatal: make(chan error, 1),
					cancel: cancel, closePipe: func() error { pipeClosed.Store(true); return nil },
					join:     func() { <-served; joined.Store(true) },
					finalize: sync.OnceValue(func() error { return exitErr }),
					release: func() error {
						if !pipeClosed.Load() || !joined.Load() {
							return errors.New("ownership released before pipe and clients closed")
						}
						released.Store(true)
						return session.Close()
					},
				})
			}()
			tun.fault <- scenario.cause
			var terminal protocol.Terminal
			if err := dec.Decode(&terminal); err != nil {
				t.Fatal(err)
			}
			if terminal.Type != "stopped" || terminal.Reason != AdapterLostReason || terminal.Instance != s.Instance || terminal.Epoch != epoch {
				t.Fatalf("wrong terminal contract: %+v", terminal)
			}
			failed := scenario.failJournal || scenario.failClose || scenario.failExit
			if (terminal.CleanupError != "") != failed {
				t.Fatalf("cleanup result masked: %+v", terminal)
			}
			if e.Table.Applied() != nil || fatals.Load() != 0 {
				t.Fatal("forwarding remained active or adapter loss entered generic fatal")
			}
			if routes.cleaned.Load() == scenario.failJournal || (len(objects.live) != 0) != scenario.failJournal {
				t.Fatal("journal cleanup did not determine ownership result")
			}
			// No finalizer/GC/test cleanup has run: the same kernel object now
			// has only our witness, independently proving engine handle closure.
			if count := lossObjectHandles(t, witness); count != 1 {
				t.Fatalf("engine leaked native TUN handle: %d", count)
			}
			if released.Load() {
				t.Fatal("ownership released before terminal receipt")
			}
			if err := enc.Encode(protocol.Request{ID: "ack", Method: "terminalAck", Instance: s.Instance, Epoch: epoch, OpID: terminal.OpID}); err != nil {
				t.Fatal(err)
			}
			exit := <-stopped
			_, clean := exit.(*AdapterLostError)
			if clean == failed {
				t.Fatalf("cleanup failure has clean exit classification: %v", exit)
			}
			if !released.Load() {
				t.Fatal("ownership not released after transport join")
			}
		})
	}
}

func TestAdapterLossHandoffIsIdempotentAndLeavesOtherErrorsFatal(t *testing.T) {
	loss := newAdapterLoss()
	if loss.handle(errors.New("unrelated failure")) || loss.handle(wintun.ErrCorrupt) {
		t.Fatal("generic failure classified as adapter loss")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { loss.handle(fmt.Errorf("pump: %w", wintun.ErrAdapterRemoved)) })
	}
	wg.Wait()
	if len(loss.ready) != 1 || loss.cause.Load() == nil {
		t.Fatal("loss handoff was not exactly once")
	}
	if (&AdapterLostError{Cause: wintun.ErrAdapterRemoved}).EngineExitCode() != 2 {
		t.Fatal("wrong fallback exit status")
	}
}
