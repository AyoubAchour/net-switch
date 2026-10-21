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
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
)

type Runtime struct {
	*engine.Engine
	routes *Routes
	owners *Owners
	dialer *Dialer
}

func (r *Runtime) Stats() any {
	stats := r.Engine.Stats().(map[string]any)
	stats["ownerLookup"] = r.owners.Stats()
	stats["socketResources"] = r.dialer.ports.stats()
	stats["udpSocketExhaustions"] = r.dialer.udpExhaustions.Load()
	if failure := r.dialer.udpFailure.Load(); failure != nil {
		stats["udpAllocationFailure"] = failure
	}
	if winhandle.Enabled {
		stats["handleOwnership"] = winhandle.Stats()
	}
	stats["bindings"] = r.routes.Bindings()
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

func Serve(parent context.Context, dir string, standalone bool) (err error) {
	initStarted := winclock.Now()
	if !Elevated() {
		return errors.New("engine requires SYSTEM or an elevated administrator")
	}
	stateStarted := winclock.Now()
	state, err := StateDirectory(dir)
	stateElapsed := winclock.Since(stateStarted)
	if err != nil {
		return err
	}
	closeState := sync.OnceValue(state.Close)
	defer func() { err = joinShutdownError(err, closeState()) }()
	routes, err := recoverRoutes(dir)
	if err != nil {
		return err
	}
	closeRoutes := sync.OnceValue(routes.Close)
	defer func() { err = joinShutdownError(err, closeRoutes()) }()
	routes.timings.record("state.directory", stateElapsed)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	owners := NewOwners()
	// Allocate the completion service before any capture can start. A failure
	// here leaves ordinary OS routing in place instead of rejecting every flow.
	dialer, err := NewDialer(routes)
	if err != nil {
		return fmt.Errorf("initialize Windows socket readiness: %w", err)
	}
	closeDialer := sync.OnceValue(dialer.Close)
	defer func() { err = joinShutdownError(err, closeDialer()) }()
	e := engine.New(ctx, engine.Dependencies{OpenTun: routes.OpenTun, Routes: routes, Dialer: dialer, Owners: owners, Identities: owners},
		flows.Defaults(), flows.FileState{Path: filepath.Join(dir, "engine-state.json"), SyncParent: SyncParent})
	loss := newAdapterLoss()
	e.OnTunError = loss.handle
	runtime := &Runtime{Engine: e, routes: routes, owners: owners, dialer: dialer}
	server := protocol.New(runtime, e.Table, dialer)
	// The ownership records and command fence identify this same engine.
	// NewRoutes receives the instance before any OS object can be created.
	server.Instance = routes.Instance
	routes.Table = e.Table
	fatal := make(chan error, 1)
	fail := func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	e.OnFatal, routes.Fatal, server.OnCleanupFailure = fail, fail, fail
	stopProfile, err := startHeapProfile(routes.Instance, standalone)
	if err != nil {
		return err
	}
	stopProfile = sync.OnceValue(stopProfile)
	defer func() { err = joinShutdownError(err, stopProfile()) }()
	pipe, err := ListenPipe(EnginePipe, standalone)
	if err != nil {
		return err
	}
	closePipe := sync.OnceValue(pipe.Close)
	defer func() { err = joinShutdownError(err, closePipe()) }()
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
	log.Printf("engine %s ready; pid control uses authenticated pipe %s", server.Instance, EnginePipe)
	return serveUntilStopped(parent, shutdownTail{
		runtime: runtime, server: server, loss: loss, fatal: fatal,
		cancel: cancel, closePipe: closePipe,
		join:     func() { <-acceptDone; clients.Wait(); <-leaseDone },
		finalize: sync.OnceValue(func() error { return errors.Join(stopProfile(), closeDialer()) }),
		release:  func() error { return errors.Join(closeRoutes(), closeState()) },
	})
}
