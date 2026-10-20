package lifecycle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
	"github.com/AyoubAchour/net-switch/internal/faultpoint"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func EngineService(ctx context.Context, ready func(), c Config, log func(string)) error {
	lockCtx, lockCancel := context.WithTimeout(ctx, 10*time.Second)
	defer lockCancel()
	release, err := (Lock{Data: c.Data, Name: "engine"}).Acquire(lockCtx)
	if err != nil {
		return err
	}
	releaseSafe := true
	defer func() {
		if releaseSafe {
			_ = release()
		}
	}()
	boot, err := BootID()
	if err != nil {
		return err
	}
	// The stand-in owns a guarded child scope. Its TUN belongs to that child's
	// kernel handles; native platform object journals are supplied at M4.
	store := &journal.FileStore{Path: filepath.Join(c.Data, "engine-journal.json"), SyncParent: SyncDirectory}
	records, err := store.Records()
	if err != nil {
		return err
	}
	if err = retireAdapterScopes(store, records); err != nil {
		return err
	}
	if err = removeRetiredAdapterFolders(c.Data); err != nil {
		return err
	}
	if err = store.ClearRetired(); err != nil {
		return err
	}
	runtime := &adapterRuntime{data: c.Data}
	var previous engineState
	if err := readEngineState(c.Data, &previous, log); err != nil {
		return err
	}
	runtime.state.Epoch = previous.Epoch
	runtime.state.Applied = previous.Applied // history; hello reads only the live adapter
	table := flows.New(flows.Defaults(), nil)
	server := protocol.New(runtime, table, nil)
	runtime.state.Instance = server.Instance
	instanceDir := filepath.Join(c.Data, "adapter-"+server.Instance)
	if err = os.Mkdir(instanceDir, 0700); err != nil {
		return err
	}
	base := nativePlatform(c, log)
	runtime.adapter = singbox.New(singbox.Options{Executable: c.Adapter, DataDir: instanceDir, Mode: c.Mode, Platform: base, Log: log, StartProcess: startAdapter, NormalizeProcessPath: normalizeAdapterPath, PrepareConfig: adapterOwnership(c, store, boot, server.Instance)})
	record := journal.Record{ID: randomID(), Boot: boot, Instance: server.Instance, Kind: "adapter-service-scope", Fingerprint: journal.Fingerprint{"service": service.Engine, "executable": c.Adapter, "directory": instanceDir, "lifetime": "kernel-guard"}, Phase: "intent"}
	if err = store.Append(record); err != nil {
		return err
	}
	if err = Save(filepath.Join(c.Data, "engine-state.json"), runtime.state); err != nil {
		return err
	}
	listener, err := localipc.Listen(localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
	if err != nil {
		return err
	}
	defer listener.Close()
	record.Phase = "created"
	if err = store.Append(record); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go server.RunLease(runCtx)
	accepted := make(chan error, 1)
	go func() {
		accepted <- accept(runCtx, listener, func(conn *localipc.Conn) {
			// The pipe ACL/socket mode and a second identity check protect attach.
			if conn.Peer.User != "0" && conn.Peer.User != "S-1-5-18" {
				conn.Close()
				return
			}
			if err := server.Serve(runCtx, conn); err != nil && runCtx.Err() == nil {
				log("engine IPC: " + err.Error())
			}
		}, log)
	}()
	ready()
	watch := time.NewTicker(time.Second)
	defer watch.Stop()
	var result error
	var health healthWatch
	suspended := false
running:
	for {
		select {
		case event := <-service.Events(ctx):
			if event.Suspend || event.Resume {
				health = healthWatch{}
				suspended = event.Suspend
			}
			if event.Resume {
				owner, err := LoadOwner(c.Data)
				if err != nil {
					log("resume owner lookup: " + err.Error())
					continue
				}
				resumeEngine(server, owner.User, sessionPresence(c.Data), log)
			}
		case <-ctx.Done():
			break running
		case <-server.Done():
			break running
		case result = <-accepted:
			break running
		case <-watch.C:
			if server.Expired() {
				result = errors.New("control lease expired")
				break running
			}
			if s := runtime.adapter.Snapshot(); s.Status == "error" {
				result = errors.New("guarded adapter failed")
				if s.Error != nil {
					result = errors.New(*s.Error)
				}
				break running
			}
			if !suspended && runtime.adapter.Snapshot().Status == "on" {
				if err := health.check(runCtx, runtime.adapter, time.Now); err != nil {
					runtime.adapter.Fail(err)
					result = err
					log(err.Error())
					break running
				}
			} else {
				health = healthWatch{}
			}
		}
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	stopped := make(chan error, 1)
	go func() {
		var recordErr error
		if server.LeaseExpired() || result != nil {
			runtime.mu.Lock()
			runtime.state.ExitReason = "adapter-failed"
			if server.LeaseExpired() {
				runtime.state.ExitReason = "lease-expired"
			}
			recordErr = Save(filepath.Join(c.Data, "engine-state.json"), runtime.state)
			runtime.mu.Unlock()
			if server.LeaseExpired() {
				log("control lease expired; cleaning up without counting an engine failure")
			}
		}
		stopped <- errors.Join(recordErr, runtime.Stop(stopCtx))
	}()
	select {
	case err := <-stopped:
		if err != nil {
			releaseSafe = false
			return errors.Join(result, err)
		}
	case <-stopCtx.Done():
		// Keep the OS ownership lock until the process exits. A timed-out
		// cleanup goroutine must not overlap another engine's startup.
		releaseSafe = false
		return errors.Join(result, fmt.Errorf("engine cleanup timed out; exiting to release the guarded child: %w", stopCtx.Err()))
	}
	cancel()
	listener.Close()
	records, err = store.Records()
	if err != nil {
		return errors.Join(result, err)
	}
	if err := retireAdapterScopes(store, records); err != nil {
		return errors.Join(result, err)
	}
	record.Phase = "removed"
	if err := store.Append(record); err != nil {
		return errors.Join(result, err)
	}
	faultpoint.Hit(c.Data, "engine-after-stop-cleanup")
	return result
}

func resumeEngine(server interface{ Resume() }, owner string, present func(string, uint32) (bool, error), log func(string)) {
	signedIn, err := present(owner, ^uint32(0))
	if err != nil {
		log("resume owner session check: " + err.Error())
	}
	if err == nil && !signedIn {
		log("resume without an owner session; Control decides routing intent")
		return
	}
	server.Resume()
	log("power resume: ten-second lease renewal grace")
}

func readEngineState(data string, state *engineState, log func(string)) error {
	path := filepath.Join(data, "engine-state.json")
	err := Read(path, state)
	if err == nil {
		return nil
	}
	// Decode the backup into fresh state; a partial primary decode must not
	// leak fields into the restored epoch/history.
	var backup engineState
	backupErr := Read(path+".bak", &backup)
	if backupErr == nil {
		*state = backup
		log("engine state restored from protected backup: " + err.Error())
		return nil
	}
	if os.IsNotExist(err) && os.IsNotExist(backupErr) {
		return nil
	}
	return fmt.Errorf("engine state and backup unreadable: %w", errors.Join(err, backupErr))
}

func removeRetiredAdapterFolders(data string) error {
	entries, err := os.ReadDir(data)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if len(name) != len("adapter-")+32 || name[:8] != "adapter-" {
			continue
		}
		if _, err := hex.DecodeString(name[8:]); err != nil {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			return fmt.Errorf("unexpected retired adapter path %s", name)
		}
		if err := os.RemoveAll(filepath.Join(data, name)); err != nil {
			return err
		}
	}
	return nil
}

func retireAdapterScopes(store *journal.FileStore, records []journal.Record) error {
	pending := map[string]journal.Record{}
	for _, record := range records {
		if record.Kind != "adapter-service-scope" && record.Kind != "adapter-linux-rule" {
			return fmt.Errorf("cleanup driver for %q belongs to the native platform; refusing to guess", record.Kind)
		}
		if record.Instance == "" || record.Kind == "adapter-service-scope" && (record.Fingerprint["service"] != service.Engine || record.Fingerprint["lifetime"] != "kernel-guard") {
			return errors.New("invalid adapter lifetime fingerprint")
		}
		if record.Phase == "removed" {
			delete(pending, record.ID)
		} else {
			pending[record.ID] = record
		}
	}
	for _, record := range pending {
		if record.Kind == "adapter-linux-rule" {
			if err := removeAdapterRule(record); err != nil {
				return err
			}
		}
		record.Phase = "removed"
		if err := store.Append(record); err != nil {
			return err
		}
	}
	return nil
}
func Cleanup(ctx context.Context, data string) error {
	// The lifetime lock is held before the listener exists and until cleanup
	// is complete. Recovery never cleans a live engine, including startup.
	release, err := (Lock{Data: data, Name: "engine"}).Acquire(ctx)
	if err != nil {
		return fmt.Errorf("engine is live or recovery is busy: %w", err)
	}
	defer release()
	store := &journal.FileStore{Path: filepath.Join(data, "engine-journal.json"), SyncParent: SyncDirectory}
	records, err := store.Records()
	if err != nil {
		return err
	}
	return retireAdapterScopes(store, records)
}
