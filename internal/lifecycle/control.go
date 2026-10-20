package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/control"
	"github.com/AyoubAchour/net-switch/internal/crashnet"
	"github.com/AyoubAchour/net-switch/internal/faultpoint"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/updates"
)

func ControlService(serviceCtx context.Context, ready func(), c Config, log func(string)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner, err := LoadOwner(c.Data)
	if err != nil {
		return err
	}
	remote := NewRemote(ctx, log)
	// Attach before considering any cleanup or new start. A Control restart
	// must preserve the engine's existing flows and fixed closure cutoffs.
	attachCtx, stopAttach := context.WithTimeout(ctx, 10*time.Second)
	defer stopAttach()
	status, statusErr := service.Query(service.Engine)
	if statusErr != nil {
		return fmt.Errorf("query engine before reattachment: %w", statusErr)
	}
	if status.PID != 0 || status.Running {
		for {
			err = remote.Attach(attachCtx, false)
			if err == nil {
				break
			}
			if waitErr := localipc.Pause(attachCtx, 200*time.Millisecond); waitErr != nil {
				stopAttach()
				return fmt.Errorf("live engine could not be reattached; journal left intact: %w", err)
			}
		}
	} else {
		err = errors.New("engine service is stopped")
	}
	stopAttach()
	wasRunning := err == nil && remote.Snapshot().Status == "on"
	if err != nil {
		log("no existing engine attachment: " + err.Error())
	}
	ioOptions := settings.Options{Files: durableFiles{}, SyncFile: syncFile, SyncParent: SyncDirectory, OnBackupError: func(err error) { log("backup: " + err.Error()) }}
	store := settings.New(c.Data, ioOptions)
	if _, err := store.Load(); err != nil {
		return err
	}
	journalOptions := ioOptions
	journalOptions.FileName = "control-journal.json"
	journalOptions.Defaults = map[string]any{"revision": 0, "closures": []any{}}
	journal := settings.New(c.Data, journalOptions)
	if _, err := journal.Load(); err != nil {
		return err
	}
	if journal.Recovery != nil {
		if !journal.Recovery.UsedBackup {
			return fmt.Errorf("control journal needs administrator recovery: %s", journal.Recovery.Reason)
		}
		log("control journal restored from its protected backup: " + journal.Recovery.Reason)
	}
	undoOptions := ioOptions
	undoOptions.FileName = "windows-undo.json"
	undoOptions.Defaults = map[string]any{"metrics": map[string]any{}, "policy": map[string]any{}}
	undo := settings.New(c.Data, undoOptions)
	if _, err := undo.Load(); err != nil {
		return err
	}
	desktop := &DesktopBridge{Base: nativePlatform(c, log)}
	boot, err := BootID()
	if err != nil {
		return err
	}
	// A Control failure releases its connection, not the engine. The service
	// manager gets the first recovery opportunity; the lease is the fallback.
	crash := crashnet.New(log, func(context.Context) error { cancel(); return nil })
	core, err := control.New(ctx, control.Options{Engine: remote, Platform: desktop, Settings: store, Undo: undo, Journal: journal, IO: ioOptions, Mode: c.Mode, Version: assets.AppVersion(), UserDir: c.Data, Log: log, Crash: crash, ServiceMode: true, BootID: boot, AutostartAllowed: true, Checkpoint: func(point string) { faultpoint.Hit(c.Data, point) }, CheckUpdate: func(ctx context.Context) (*updates.Offer, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		architecture, err := desktop.Base.Call(ctx, "architecture", nil)
		if err != nil {
			return nil, err
		}
		return updates.Check(ctx, assets.AppVersion(), fmt.Sprint(architecture))
	}})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:47821")
	if err != nil {
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		return err
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	tokens := NewTokens()
	defer tokens.RevokeAll()
	access := &Access{Core: core, Remote: remote, Owner: owner, Tokens: tokens, Desktop: desktop, Port: port, Data: c.Data}
	quit := make(chan struct{})
	var quitOnce sync.Once
	httpHandler := &control.HTTP{Core: core, Port: port, ValidToken: tokens.Valid, Pair: tokens.Redeem, Asset: ServiceAsset, Quit: func() { quitOnce.Do(func() { close(quit) }) }}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pair" || r.URL.Path == "/pair.js" || r.URL.Path == "/pair.css" {
			servePair(w, r, port)
			return
		}
		httpHandler.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second}
	defer server.Close()
	failures := make(chan error, 4)
	go func() { defer crash.Recover("service HTTP"); failures <- server.Serve(listener) }()
	paths := []string{"desktop"}
	if runtime.GOOS == "windows" {
		paths = append(paths, "status")
	}
	var listeners []localipc.Listener
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	var workers sync.WaitGroup
	for _, kind := range paths {
		l, err := localipc.Listen(localipc.Endpoint{Path: localipc.DefaultPath(kind), Kind: kind, Owner: owner.User, Service: service.Control})
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		workers.Go(func() {
			failures <- accept(ctx, l, func(conn *localipc.Conn) { access.serve(ctx, conn, kind == "status") }, log)
		})
	}
	core.CheckElevation(ctx)
	if err := core.RefreshAdapters(ctx); err != nil {
		log("initial adapter scan: " + err.Error())
	}
	if err := core.ApplyPolicy(ctx); err != nil {
		return err
	}
	if wasRunning {
		if err := core.ResumeRouting(ctx); err != nil {
			return err
		}
	}
	core.Run()
	ready()
	// No credential, HTTP port or session token is published to a file.
	log(fmt.Sprintf("Control ready (PID %d); owner=%s", os.Getpid(), owner.Name))
	alreadyStopped := false
	select {
	case err = <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case err = <-crash.Failures():
		return err // preserve the lease while SCM restarts Control
	case <-serviceCtx.Done():
	case <-quit:
		alreadyStopped = true
	}
	shutdown, stop := context.WithTimeout(context.Background(), 25*time.Second)
	defer stop()
	if !alreadyStopped {
		if shutdownErr := core.Shutdown(shutdown); shutdownErr != nil {
			return errors.Join(err, shutdownErr)
		}
	}
	_ = server.Shutdown(shutdown)
	cancel()
	for _, l := range listeners {
		l.Close()
	}
	workers.Wait()
	return err
}

func Log(data, process string) func(string) {
	var mu sync.Mutex
	return func(message string) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintln(os.Stderr, message)
		path := filepath.Join(data, process+".log")
		if info, err := os.Stat(path); err == nil && info.Size() > 5<<20 {
			_ = os.Remove(path + ".old")
			_ = os.Rename(path, path+".old")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), message)
			f.Close()
		}
	}
}
