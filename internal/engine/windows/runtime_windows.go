//go:build windows

package winengine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
)

type Runtime struct {
	*engine.Engine
	routes *Routes
	owners *Owners
	dialer *Dialer
	state  host.State
}

func (r *Runtime) InitialEpoch() uint64 {
	if r.state == nil {
		return 0
	}
	return r.state.InitialEpoch()
}
func (r *Runtime) SaveEpoch(epoch uint64) error {
	if r.state == nil {
		return nil
	}
	return r.state.SaveEpoch(epoch)
}

func (r *Runtime) Stats() any {
	stats := r.Engine.Stats().(map[string]any)
	stats["ownerLookup"] = r.owners.Stats()
	stats["socketResources"] = r.dialer.ports.stats()
	stats["udpSocketExhaustions"] = r.dialer.udpExhaustions.Load()
	// Refused automatic port choices, per protocol (SYSTEM-DESIGN 5.9): first
	// refusals, fresh attempts and final failures; each final one is listed
	// with its flow in finalPortRefusals.
	stats["udpBindRetries"] = r.dialer.udpRetries.stats()
	stats["tcpDialRetries"] = r.dialer.tcpRetries.stats()
	stats["finalPortRefusals"] = r.dialer.refusals.stats()
	stats["udpSendFailures"] = udpSendFailureStats()
	if failure := r.dialer.udpFailure.Load(); failure != nil {
		stats["udpAllocationFailure"] = failure
	}
	if winhandle.Enabled {
		stats["handleOwnership"] = winhandle.Stats()
	}
	stats["bindings"], stats["bindingsTruncated"] = statsBindings(r.routes.Bindings())
	stats["wintun"] = r.routes.TunStats()
	stats["lifecyclePhases"] = r.routes.timings.snapshot()
	if trace := r.routes.trace.snapshot(); trace != nil {
		stats["packetTrace"] = trace
		stats["nativeSocketState"] = nativeSocketState()
		stats["nativeUDPState"] = nativeUDPState()
		stats["nativeReadiness"] = r.dialer.pool.stats()
		stats["nativeUDPReadiness"] = r.dialer.udp.stats()
	}
	if memory, err := processMemory(); err == nil {
		stats["processMemory"] = memory
	} else {
		stats["processMemoryError"] = err.Error()
	}
	return stats
}

// statsBindings gives each line's binding a fixed bound in stats, so the
// policy's 255 lines stay bounded however many addresses Windows lists: the
// alias at 256 bytes and each address list at its first 8. Lines cut are
// named.
func statsBindings(b map[string]Adapter) (map[string]Adapter, []string) {
	var truncated []string
	for id, a := range b {
		if len(a.Alias) > 256 || len(a.Addresses) > 8 || len(a.Valid) > 8 {
			truncated = append(truncated, id)
		}
		a.Alias = engine.Clip(a.Alias, 256)
		a.Addresses = a.Addresses[:min(len(a.Addresses), 8)]
		a.Valid = a.Valid[:min(len(a.Valid), 8)]
		b[id] = a
	}
	return b, truncated
}

func (r *Runtime) Start(ctx context.Context, revision policy.Revision) (policy.Applied, error) {
	finish := r.routes.timings.begin("engine.start.total")
	applied, err := r.Engine.Start(ctx, revision)
	finish()
	r.routes.timings.report(r.routes.Instance, "start", err)
	return applied, err
}

func (r *Runtime) Stop(ctx context.Context) error {
	stopTrace := startStopTrace(ctx)
	defer stopTrace()
	finish := r.routes.timings.begin("engine.stop.total")
	err := r.Engine.Stop(ctx)
	finish()
	r.routes.timings.report(r.routes.Instance, "stop", err)
	return err
}

func recoverRoutes(dir string) (*Routes, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return NewRoutes(newDiskJournal(filepath.Join(dir, "engine-journal.json")), OwnershipLock{}, hex.EncodeToString(id[:]))
}

func Recover(dir string) error {
	if !Elevated() {
		return errors.New("engine recovery requires elevation")
	}
	state, err := StateDirectory(dir)
	if err != nil {
		return err
	}
	defer state.Close()
	r, err := recoverRoutes(dir)
	if err != nil {
		return err
	}
	return r.Close()
}

func RecoverReported(ctx context.Context, dir string, begin func() (func(error) error, error)) error {
	state, err := StateDirectory(dir)
	if err != nil {
		return err
	}
	closeState := sync.OnceValue(state.Close)
	defer closeState()
	return host.Recover(ctx, OwnershipLock{}, func(lock journal.Locker) error {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return errors.Join(err, closeState())
		}
		r, err := NewRoutes(newDiskJournal(filepath.Join(dir, "engine-journal.json")), lock, hex.EncodeToString(nonce[:]))
		if err != nil {
			return errors.Join(err, closeState())
		}
		return errors.Join(r.Close(), closeState())
	}, begin)
}

func Serve(parent context.Context, dir string, standalone bool) (err error) {
	return ServeHosted(parent, dir, standalone, host.Options{})
}

func ServeHosted(parent context.Context, dir string, standalone bool, options host.Options) (err error) {
	options.Stage("native-enter")
	// Setup failures/panics still need the deferred closers. Once the tail has
	// completed, it owns both closure and error reporting; do not re-add each
	// cached close error to its final result.
	shutdownComplete := false
	initStarted := winclock.Now()
	if !Elevated() {
		return errors.New("engine requires SYSTEM or an elevated administrator")
	}
	stateStarted := winclock.Now()
	state, err := StateDirectory(dir)
	options.Stage("state-directory")
	stateElapsed := winclock.Since(stateStarted)
	if err != nil {
		return err
	}
	closeState := sync.OnceValue(state.Close)
	defer func() {
		if !shutdownComplete {
			err = joinShutdownError(err, closeState())
		}
	}()
	routes, err := recoverRoutes(dir)
	options.Stage("ownership-recovered")
	if err != nil {
		return err
	}
	closeRoutes := sync.OnceValue(routes.Close)
	defer func() {
		if !shutdownComplete {
			err = joinShutdownError(err, closeRoutes())
		}
	}()
	routes.timings.record("state.directory", stateElapsed)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	owners := NewOwners()
	// Allocate the completion service before any capture can start. A failure
	// here leaves ordinary OS routing in place instead of rejecting every flow.
	dialer, err := NewDialer(routes)
	options.Stage("dialer-created")
	if err != nil {
		return fmt.Errorf("initialize Windows socket readiness: %w", err)
	}
	closeDialer := sync.OnceValue(dialer.Close)
	defer func() {
		if !shutdownComplete {
			err = joinShutdownError(err, closeDialer())
		}
	}()
	var serviceState host.State
	var history flows.StateStore = flows.FileState{Path: filepath.Join(dir, "engine-state.json"), SyncParent: SyncParent}
	if options.OpenState != nil {
		options.Stage("state-open-begin")
		serviceState, err = options.OpenState(routes.Instance)
		options.Stage("state-open-end")
		if err != nil {
			return err
		}
		history = serviceState
	}
	openTun := func(ctx context.Context) (platform.TunDevice, error) {
		tun, err := routes.OpenTun(ctx)
		if err == nil && options.WrapTun != nil {
			tun = options.WrapTun(tun)
		}
		return tun, err
	}
	e := engine.New(ctx, engine.Dependencies{OpenTun: openTun, Routes: routes, Dialer: dialer, Owners: owners, Identities: owners,
		SilentSYNDiagnostics: true},
		flows.Defaults(), history)
	loss := newAdapterLoss()
	e.OnTunError = loss.handle
	runtime := &Runtime{Engine: e, routes: routes, owners: owners, dialer: dialer, state: serviceState}
	server := protocol.New(runtime, e.Table, dialer)
	options.Stage("protocol-created")
	// The ownership records and command fence identify this same engine.
	// NewRoutes receives the instance before any OS object can be created.
	server.Instance = routes.Instance
	routes.Table = e.Table
	if options.Configure != nil {
		options.Configure(server, e.Table)
	}
	fatal := make(chan error, 1)
	fail := func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	e.OnFatal, routes.Fatal, server.OnCleanupFailure = fail, fail, fail
	stopProfile, err := startHeapProfile(routes.Instance, standalone)
	options.Stage("profile-created")
	if err != nil {
		return err
	}
	stopProfile = sync.OnceValue(stopProfile)
	defer func() {
		if !shutdownComplete {
			err = joinShutdownError(err, stopProfile())
		}
	}()
	pipe, err := ListenPipe(EnginePipe, standalone)
	options.Stage("pipe-created")
	if err != nil {
		return err
	}
	closePipe := sync.OnceValue(pipe.Close)
	defer func() {
		if !shutdownComplete {
			err = joinShutdownError(err, closePipe())
		}
	}()
	stopListen := context.AfterFunc(ctx, func() { closePipe() })
	defer stopListen()
	routes.timings.record("engine.init.total", winclock.Since(initStarted))
	leaseDone := make(chan struct{})
	go func() { defer close(leaseDone); server.RunLease(ctx) }()
	var clients sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := pipe.Accept(ctx)
			if err != nil {
				if errors.Is(err, errPeerRefused) {
					log.Print(err)
					continue
				}
				if ctx.Err() == nil {
					fail(fmt.Errorf("engine pipe: %w", err))
				}
				return
			}
			clients.Go(func() {
				if err := server.Serve(ctx, conn); err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
					log.Printf("controller disconnected: %v", err)
				}
			})
		}
	}()
	options.Stage("ready-log-begin")
	log.Printf("engine %s ready; pid control uses authenticated pipe %s", server.Instance, EnginePipe)
	options.Stage("ready-log-end")
	if options.Ready != nil {
		options.Stage("ready-callback-begin")
		options.Ready(server)
		options.Stage("ready-callback-end")
	}
	err = serveUntilStopped(parent, shutdownTail{
		runtime: runtime, server: server, loss: loss, fatal: fatal,
		cancel: cancel, closePipe: closePipe,
		join:     func() { <-acceptDone; clients.Wait(); <-leaseDone },
		finalize: sync.OnceValue(func() error { return errors.Join(stopProfile(), closeDialer()) }),
		release:  func() error { return errors.Join(closeRoutes(), closeState()) },
	})
	shutdownComplete = true
	return err
}
