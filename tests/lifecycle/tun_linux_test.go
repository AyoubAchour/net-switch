package lifecycle_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/tests/linux/netns"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
)

func prepareTUN(t *testing.T, _, data string) tunFixture {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(data, "tun-fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	n, err := topo.Up(ctx, hostedTestExecutable(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"netswitch.service", "netswitch-engine.service"} {
		dir := filepath.Join("/run/systemd/system", name+".d")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "namespace.conf"), []byte("[Service]\nNetworkNamespacePath=/run/netns/"+topo.DUT+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := n.R.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		_ = service.Stop(stop, service.Control)
		_ = service.Stop(stop, service.Engine)
		for _, name := range []string{"netswitch.service", "netswitch-engine.service"} {
			_ = os.Remove(filepath.Join("/run/systemd/system", name+".d", "namespace.conf"))
		}
		_, _ = n.R.Run(ctx, "systemctl", "daemon-reload")
		if err := n.Down(ctx); err != nil {
			t.Error(err)
		}
	})
	before, err := n.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return tunFixture{
		line: "eth-a", target: "198.51.100.10:7002", dial: netns.Dialer(topo.DUT),
		exchange: func(t *testing.T, c net.Conn) {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprint(c, "ping lifecycle\n"); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "pong lifecycle ") {
				t.Fatal(line, err)
			}
		},
		installed: func(t *testing.T) {
			now, err := n.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			diff := now.Diff(before)
			if len(diff) == 0 || !strings.Contains(strings.Join(diff, "\n"), "NetSwitch") {
				t.Fatal("no real TUN objects", diff)
			}
			t.Log("TUN installed routing state", diff)
		},
		clean: func(t *testing.T) {
			now, err := n.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if diff := now.Diff(before); len(diff) != 0 {
				t.Fatal("TUN cleanup left routing state", diff)
			}
		},
	}
}
