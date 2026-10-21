package lifecycle_test

import (
	"bufio"
	"context"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/service"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func desktopStartupRetry(t *testing.T, cfg lifecycle.Config, owner actor) {
	t.Helper()
	restore := blockDesktopActivation(t, cfg)
	defer restore()
	desktop := owner.command(filepath.Join(cfg.Directory, binary("netswitch-desktop")), "--background")
	output, err := desktop.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := desktop.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = desktop.Wait(); close(exited) }()
	t.Cleanup(func() { _ = desktop.Process.Kill(); <-exited })
	retrying := make(chan struct{})
	go func() {
		scan := bufio.NewScanner(output)
		for scan.Scan() {
			if strings.Contains(scan.Text(), "retrying:") {
				close(retrying)
				return
			}
		}
	}()
	select {
	case <-retrying:
	case <-exited:
		t.Fatal("desktop exited on unavailable Control")
	case <-time.After(15 * time.Second):
		t.Fatal("desktop did not diagnose and retry unavailable Control")
	}
	if s, err := service.Query(service.Control); err != nil || s.Running {
		t.Fatal("Control was not unavailable for the retry test", s, err)
	}
	restore()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	wait(t, "desktop activates Control after it becomes available", 30*time.Second, func() bool { s, e := service.Query(service.Control); return e == nil && s.Running })
	client := openClient(t, owner, false)
	defer client.input.Close()
	wait(t, "original desktop completes deferred sign-in", 30*time.Second, func() bool {
		s := getStatus(t, client)
		return s.Routing == "on" && s.DesktopPID == uint32(desktop.Process.Pid)
	})
	_ = desktop.Process.Kill()
	<-exited
	client.must(t, "routing", map[string]any{"on": false}, nil)
	if err := service.Stop(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
}
