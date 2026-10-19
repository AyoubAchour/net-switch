// Command netswitch is the milestone-one elevated control process. Packaging
// still starts Node; --dev-proxy is reserved for the existing CI launchers.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/control"
	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/platform/worker"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/updates"
)

type disk struct{}

func (disk) ReadFile(p string) ([]byte, error)                 { return os.ReadFile(p) }
func (disk) WriteFile(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }
func (disk) Rename(a, b string) error                          { return os.Rename(a, b) }
func (disk) Remove(p string) error                             { return os.Remove(p) }

type logger struct {
	mu   sync.Mutex
	path string
}

func (l *logger) append(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if info, err := os.Stat(l.path); err == nil && info.Size() > 5*1024*1024 {
		_ = os.Remove(l.path + ".old")
		_ = os.Rename(l.path, l.path+".old")
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), s)
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		os.Exit(win.Run(os.Args[2:]))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("netswitch", flag.ContinueOnError)
	version := flags.Bool("version", false, "print build identity")
	dev := flags.Bool("dev-proxy", false, "CI proxy mode with separate ports and data")
	root := flags.String("root", "", "application root (defaults to the working directory)")
	user := flags.String("user-data", "", "settings and session folder")
	machine := flags.String("machine-data", "", "engine and undo folder")
	engineDir := flags.String("engine-dir", "", "verified sing-box folder (test mode only)")
	engineExe := flags.String("engine-executable", "", "exact verified engine executable (CI only)")
	background := flags.Bool("background", false, "start the registered server task and existing tray at sign-in")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *version {
		fmt.Printf("Net Switch control %s (build %s; %s/%s; %s)\n", assets.AppVersion(), buildinfo.String(), runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Linux control-service platform support is not implemented yet")
	}
	if *root == "" {
		var err error
		*root, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	var err error
	*root, err = filepath.Abs(*root)
	if err != nil {
		return err
	}
	mode, sub, port, lockPort := "tun", "data", 47821, 47820
	if *dev {
		mode, sub, port, lockPort = "proxy", "data-test", 47831, 47830
	}
	defaultDir := filepath.Join(*root, sub)
	if *user == "" {
		*user = defaultDir
	}
	if *machine == "" {
		*machine = defaultDir
	}
	*user, err = filepath.Abs(*user)
	if err != nil {
		return err
	}
	*machine, err = filepath.Abs(*machine)
	if err != nil {
		return err
	}
	if *background {
		if err := win.RunServerTask(); err != nil {
			return err
		}
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(*user, "server.json")); err == nil {
				cmd := exec.Command(filepath.Join(*root, "tray", "NetSwitchTray.exe"), "-DataDir", *user)
				hide(cmd)
				return cmd.Start()
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("server task did not publish its session file")
	}
	if err := os.MkdirAll(*user, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(*machine, 0700); err != nil {
		return err
	}
	log := &logger{path: filepath.Join(*user, "server.log")}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if *engineDir == "" {
		*engineDir = filepath.Join(*root, "engine")
	} else if !*dev {
		return fmt.Errorf("--engine-dir requires --dev-proxy")
	}
	path := filepath.Join(*engineDir, "sing-box.exe")
	if *engineExe != "" {
		if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
			return fmt.Errorf("--engine-executable is restricted to disposable hosted CI")
		}
		path = *engineExe
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	system := &win.System{Workers: worker.Supervisor{Executable: exe, Log: func(err error) { log.append("worker: " + err.Error()) }}, EnginePath: path, Root: *root, UserDir: *user, MachineDir: *machine}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *machine != *user && !*dev {
		if _, err := system.Call(ctx, "protect-directory", map[string]any{"path": *machine}); err != nil {
			log.append("Net Switch cannot start: machine folder protection failed: " + err.Error())
			return err
		}
	}
	lock, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(lockPort))
	if err != nil {
		holder, why := system.Call(ctx, "port-holder", map[string]any{"port": lockPort})
		log.append(fmt.Sprintf("single-instance port %d is busy; holder=%v; lookup=%v; refusing a second control process", lockPort, holder, why))
		return nil
	}
	defer lock.Close()
	go func() {
		for {
			conn, err := lock.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	ioOptions := settings.Options{Files: disk{}, OnBackupError: func(err error) { log.append("could not write backup: " + err.Error()) }}
	store := settings.New(*user, ioOptions)
	if _, err := store.Load(); err != nil {
		return err
	}
	undoOptions := ioOptions
	undoOptions.FileName = "windows-undo.json"
	undoOptions.Defaults = map[string]any{"metrics": map[string]any{}, "policy": map[string]any{}}
	undo := settings.New(*machine, undoOptions)
	if _, err := undo.Load(); err != nil {
		return err
	}
	journalOptions := ioOptions
	journalOptions.FileName = "control-journal.json"
	journalOptions.Defaults = map[string]any{"revision": float64(0), "desired": map[string]any{}, "settings": map[string]any{}, "closures": []any{}}
	journal := settings.New(*machine, journalOptions)
	if _, err := journal.Load(); err != nil {
		return err
	}
	engineLog := &logger{path: filepath.Join(*machine, "engine.log")}
	adapter := singbox.New(singbox.Options{Executable: path, DataDir: *machine, Mode: mode, Platform: system, Log: engineLog.append, Files: ioOptions})
	installed := false
	if pf := os.Getenv("ProgramFiles"); pf != "" && !*dev {
		rel, err := filepath.Rel(pf, *root)
		installed = err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) && *user != defaultDir
	}
	core, err := control.New(ctx, control.Options{Engine: adapter, Platform: system, Settings: store, Undo: undo, Journal: journal, IO: ioOptions, Mode: mode, Version: assets.AppVersion(), UserDir: *user, Log: log.append, AutostartAllowed: installed, CheckUpdate: func(ctx context.Context) (*updates.Offer, error) { return checkUpdate(ctx, system) }})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		return err
	}
	defer listener.Close()
	port = listener.Addr().(*net.TCPAddr).Port
	var entropy [24]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(entropy[:])
	quit := make(chan struct{})
	var once sync.Once
	handler := &control.HTTP{Core: core, Port: port, Token: token, Quit: func() { once.Do(func() { close(quit) }) }}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	core.CheckElevation(ctx)
	if err := core.RefreshAdapters(ctx); err != nil {
		log.append("initial adapter scan failed: " + err.Error())
	}
	core.RefreshAutostart(ctx)
	if err := core.ApplyPolicy(ctx); err != nil {
		return err
	}
	message, err := core.PublishSession(port, token, os.Getpid())
	if err != nil {
		return err
	}
	fmt.Println(message)
	core.Run()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-quit:
	case <-signals:
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := core.Shutdown(stopCtx); err != nil {
			return err
		}
	case err := <-serveErr:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}
func checkUpdate(ctx context.Context, system *win.System) (*updates.Offer, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/AyoubAchour/net-switch/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("User-Agent", "NetSwitch/"+assets.AppVersion())
	r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		return nil, nil
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub answered %d", response.StatusCode)
	}
	var release map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(&release); err != nil {
		return nil, err
	}
	arch, err := system.Call(ctx, "architecture", nil)
	if err != nil {
		return nil, err
	}
	return updates.OfferFrom(release, assets.AppVersion(), js.Text(arch)), nil
}
