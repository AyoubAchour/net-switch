package lifecycle_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/service"
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
	// Empty but referenced tables belong to other policies too. Keep these
	// foreign rules across start/cleanup and require a different allocation.
	for _, args := range [][]string{
		{"-4", "rule", "add", "pref", "100", "fwmark", "1", "lookup", "3110"},
		{"-4", "rule", "add", "pref", "110", "fwmark", "1", "prohibit"},
		{"-4", "rule", "add", "pref", "9100", "fwmark", "2", "prohibit"},
	} {
		if _, err := n.R.IP(ctx, topo.DUT, args...); err != nil {
			t.Fatal(err)
		}
	}
	beforeNumeric := map[string]bool{}
	for _, family := range []string{"-4", "-6"} {
		text, err := n.R.IP(ctx, topo.DUT, "-N", family, "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(text, "\n") {
			beforeNumeric[family+" "+strings.Join(strings.Fields(line), " ")] = true
		}
	}
	before, err := n.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "traffic.sock")
	relay := exec.Command("ip", "netns", "exec", topo.DUT, hostedTestExecutable(), "tun-relay", socket)
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Process.Kill(); _ = relay.Wait() })
	wait(t, "namespace traffic relay", 5*time.Second, func() bool { _, err := os.Stat(socket); return err == nil })
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err = fmt.Fprintln(conn, address); err != nil {
			conn.Close()
			return nil, err
		}
		var ack [3]byte
		if _, err = io.ReadFull(conn, ack[:]); err != nil || string(ack[:]) != "OK\n" {
			conn.Close()
			return nil, fmt.Errorf("namespace dial %s: %v %q", address, err, ack)
		}
		conn.SetDeadline(time.Time{})
		return conn, nil
	}
	return tunFixture{
		line: "eth-a", target: "198.51.100.10:7002", dial: dial,
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
			records, err := (&journal.FileStore{Path: filepath.Join(data, "engine-journal.json")}).Records()
			if err != nil {
				t.Fatal(err)
			}
			intent := map[string]bool{}
			for _, record := range records {
				if record.Kind == "adapter-linux-rule" && record.Phase == "intent" {
					intent[record.Fingerprint["family"]+" "+record.Fingerprint["rule"]] = true
				}
			}
			exercised := 0
			for _, family := range []string{"-4", "-6"} {
				text, err := n.R.IP(ctx, topo.DUT, "-N", family, "rule", "show")
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(text, "\n") {
					normalized := strings.Join(strings.Fields(line), " ")
					if normalized != "" && !beforeNumeric[family+" "+normalized] {
						if !intent[family+" "+normalized] {
							t.Fatal("live adapter rule has no pre-start intent", family, normalized)
						}
						exercised++
					}
				}
			}
			if exercised != 16 {
				t.Fatal("TUN fixture did not exercise the complete 16-rule adapter contract", exercised)
			}
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

// The namespace stays in this disposable subprocess. Entering it on a Go
// thread of the harness can make ip netns pids identify the harness itself,
// which would invalidate the cleanup test by killing its own observer.
func tunRelay(path string) error {
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			reader := bufio.NewReader(c)
			target, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			out, err := net.DialTimeout("tcp4", strings.TrimSpace(target), 5*time.Second)
			if err != nil {
				fmt.Fprint(c, "NO\n")
				return
			}
			defer out.Close()
			if _, err := fmt.Fprint(c, "OK\n"); err != nil {
				return
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(out, reader); out.Close(); close(done) }()
			_, _ = io.Copy(c, out)
			c.Close()
			<-done
		}()
	}
}
