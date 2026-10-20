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
	"runtime"
	"runtime/metrics"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/journal"
)

type Runtime struct {
	*engine.Engine
	routes *Routes
	owners *Owners
}

func (r *Runtime) Stats() any {
	stats := r.Engine.Stats().(map[string]any)
	stats["ownerLookup"] = r.owners.Stats()
	stats["bindings"] = r.routes.Bindings()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	stats["heapBytes"], stats["stackBytes"] = memory.HeapAlloc, memory.StackInuse
	stats["runtimeBytes"] = memory.Sys - memory.HeapReleased
	stats["gcCPUppm"] = uint64(memory.GCCPUFraction * 1e6)
	stats["goroutines"] = runtime.NumGoroutine()
	samples := []metrics.Sample{{Name: "/gc/heap/live:bytes"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	stats["heapLiveBytes"] = samples[0].Value.Uint64()
	stats["gcCPUNanos"] = uint64(samples[1].Value.Float64() * 1e9)
	stats["totalCPUNanos"] = uint64(samples[2].Value.Float64() * 1e9)
	return stats
}

func recoverRoutes(dir string) (*Routes, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return NewRoutes(&journal.FileStore{Path: filepath.Join(dir, "engine-journal.json"), SyncParent: SyncParent}, OwnershipLock{}, hex.EncodeToString(id[:]))
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
	if !Elevated() {
		return errors.New("engine requires SYSTEM or an elevated administrator")
	}
	state, err := StateDirectory(dir)
	if err != nil {
		return err
	}
	defer state.Close()
	routes, err := recoverRoutes(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, routes.Close()) }()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	owners := NewOwners()
	dialer := &Dialer{Routes: routes}
	defer func() { err = errors.Join(err, dialer.Close()) }()
	e := engine.New(ctx, engine.Dependencies{OpenTun: routes.OpenTun, Routes: routes, Dialer: dialer, Owners: owners, Identities: owners},
		flows.Defaults(), flows.FileState{Path: filepath.Join(dir, "engine-state.json"), SyncParent: SyncParent})
	runtime := &Runtime{Engine: e, routes: routes, owners: owners}
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
	pipe, err := ListenPipe(EnginePipe, standalone)
	if err != nil {
		return err
	}
	defer pipe.Close()
	stopListen := context.AfterFunc(ctx, func() { pipe.Close() })
	defer stopListen()
	go server.RunLease(ctx)
	var clients sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := pipe.Accept(ctx)
			if err != nil {
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
	select {
	case <-parent.Done():
	case <-server.Done():
	case err = <-fatal:
		log.Printf("routing stopped, restoring normal routes: %v", err)
	}
	stop, cancelStop := context.WithTimeout(context.Background(), 15*time.Second)
	err = errors.Join(err, runtime.Stop(stop))
	cancelStop()
	cancel()
	pipe.Close()
	<-acceptDone
	clients.Wait()
	return err
}
