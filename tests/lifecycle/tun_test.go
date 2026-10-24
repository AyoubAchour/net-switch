package lifecycle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/service"
)

type tunFixture struct {
	line, target               string
	churnLine, seen, churnSeen string // Linux's independent second physical path
	dial                       func(context.Context, string, string) (net.Conn, error)
	exchange                   func(*testing.T, net.Conn)
	installed                  func(*testing.T)
	clean                      func(*testing.T)
	audit                      func(*testing.T) // additional untimed OS inventory
	probe                      func(*testing.T, string) nativeProbeFixture
}

func tunServices(t *testing.T, config lifecycle.Config, owner actor, fixture tunFixture) {
	t.Helper()
	config.Mode = "tun"
	if err := lifecycle.Save(filepath.Join(config.Data, "service-config.json"), config); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"lines": []lines.Line{{ID: "a1", Alias: fixture.line, Label: "TUN fixture", Weight: 1}}, "ipv6": "off", "checkForUpdates": false}
	if err := lifecycle.Save(filepath.Join(config.Data, "settings.json"), settings); err != nil {
		t.Fatal(err)
	}
	boot, err := lifecycle.BootID()
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Save(filepath.Join(config.Data, "control-journal.json"), map[string]any{"settings": settings, "wanted": false, "bootId": boot}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	for _, failure := range []string{"engine-kill", "lease-expiry"} {
		t.Run(failure, func(t *testing.T) {
			resetControlRecoveryWindow(t)
			if err := service.Start(ctx, service.Control); err != nil {
				t.Fatal(err)
			}
			c := openClient(t, owner, false)
			defer c.input.Close()
			c.must(t, "signin", nil, nil)
			wait(t, "TUN routing on", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
			var session struct{ Token, URL string }
			c.must(t, "session", nil, &session)
			conn, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal("captured traffic failed", err)
			}
			defer conn.Close()
			fixture.exchange(t, conn)
			assertTUNCaptured(t, session.URL, session.Token, fixture)
			fixture.installed(t)
			engine, err := service.Query(service.Engine)
			if err != nil {
				t.Fatal(err)
			}
			control, err := service.Query(service.Control)
			if err != nil {
				t.Fatal(err)
			}
			restore := disableRecovery(t)
			defer restore()
			faultAt := time.Now()
			kill(t, control.PID)
			fixture.exchange(t, conn) // Control death alone must preserve the flow
			if failure == "engine-kill" {
				faultAt = time.Now()
				kill(t, engine.PID)
			}
			wait(t, "TUN engine stopped", 45*time.Second, func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
			fixture.clean(t)
			cleanAt := time.Since(faultAt)
			direct, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal("previously captured target is not direct after cleanup", err)
			}
			fixture.exchange(t, direct)
			direct.Close()
			directAt := time.Since(faultAt)
			bound := 42 * time.Second // lease 30s + one tick + bounded cleanup
			if failure == "engine-kill" {
				bound = 12 * time.Second
			}
			t.Logf("FAIL_OPEN fault=%s routes_and_adapter_gone=%s direct_traffic=%s bound=%s", failure, cleanAt, directAt, bound)
			if cleanAt > bound || directAt > bound {
				t.Fatal("fail-open exceeded bound")
			}
			if fixture.audit != nil {
				fixture.audit(t)
			}
			t.Log("TUN captured a live stream; adapter/routes/rules returned to baseline; the same target works directly")
		})
	}
	t.Run("hung-adapter-fails-open-recovers-and-latches", func(t *testing.T) {
		resetControlRecoveryWindow(t)
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c := openClient(t, owner, false)
		defer func() { c.input.Close() }()
		c.must(t, "routing", map[string]any{"on": true}, nil)
		wait(t, "TUN before hang", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
		var session struct{ Token, URL string }
		c.must(t, "session", nil, &session)
		for hang := 1; hang <= 5; hang++ {
			before := getStatus(t, c)
			live, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal(err)
			}
			fixture.exchange(t, live)
			assertTUNCaptured(t, session.URL, session.Token, fixture)
			fixture.installed(t)
			// The forwarding process is the host's verified child; suspending
			// it stalls forwarding while the host's own health checks keep
			// running, with or without Control (spec §3.4).
			pid := nativeChildPID(t, config.Data, before.Instance)
			restore := func() {}
			if hang == 1 {
				restore = disableRecovery(t)
			}
			faultAt := time.Now()
			suspendAdapter(t, pid)
			if hang == 1 {
				kill(t, before.ControlPID)
			} // health must work without Control
			wait(t, "hung engine stopped", 28*time.Second, func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
			fixture.clean(t)
			cleanAt := time.Since(faultAt)
			direct, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal("hung engine did not fail open", err)
			}
			fixture.exchange(t, direct)
			direct.Close()
			live.Close()
			if cleanAt > 28*time.Second {
				t.Fatal("health cleanup exceeded 28s", cleanAt)
			}
			if hang == 1 {
				restore()
				if err := service.Start(ctx, service.Control); err != nil {
					t.Fatal(err)
				}
				c.input.Close()
				c = openClient(t, owner, false)
			}
			wait(t, "one durable failure for this hang", 10*time.Second, func() bool {
				var j struct {
					Failures []int64 `json:"failures"`
				}
				return lifecycle.Read(filepath.Join(config.Data, "control-journal.json"), &j) == nil && len(j.Failures) >= hang
			})
			if hang < 5 {
				wait(t, "new working engine after hang", 45*time.Second, func() bool { s := getStatus(t, c); return s.Routing == "on" && s.Instance != before.Instance })
				working, err := fixture.dial(ctx, "tcp4", fixture.target)
				if err != nil {
					t.Fatal(err)
				}
				fixture.exchange(t, working)
				working.Close()
				if time.Since(faultAt) > 70*time.Second {
					t.Fatal("hang recovery exceeded 70s")
				}
			} else {
				until := time.Now().Add(32 * time.Second)
				for time.Now().Before(until) {
					s, e := service.Query(service.Engine)
					if e != nil || !s.Stopped {
						t.Fatal("fifth hang did not latch", s, e)
					}
					time.Sleep(time.Second)
				}
			}
			var j struct {
				Failures []int64 `json:"failures"`
			}
			if err := lifecycle.Read(filepath.Join(config.Data, "control-journal.json"), &j); err != nil {
				t.Fatalf("could not read the control journal: %v", err)
			}
			if len(j.Failures) != hang {
				t.Fatalf("hang counted %d times, want %d", len(j.Failures), hang)
			}
			t.Logf("HUNG_ENGINE hang=%d clean=%s recovered_or_latched=%s failures=%d control_down=%t", hang, cleanAt, time.Since(faultAt), len(j.Failures), hang == 1)
		}
	})
}

// assertTUNCaptured proves the stream went through the native engine: Control's
// own state lists this process's executable with a connection on the fixture
// line, which only the engine's paged flow listing can have told it.
func assertTUNCaptured(t *testing.T, url, token string, fixture tunFixture) {
	t.Helper()
	exe := hostedTestExecutable()
	var observed []string
	wait(t, "stream observed inside the native engine", 15*time.Second, func() bool {
		status, b := api(t, url, token, "GET", "/api/state", "")
		if status != 200 {
			return false
		}
		var state struct {
			Apps []struct {
				Path        string         `json:"path"`
				Connections map[string]int `json:"connections"`
			} `json:"apps"`
		}
		if json.Unmarshal(b, &state) != nil {
			return false
		}
		observed = observed[:0]
		for _, app := range state.Apps {
			observed = append(observed, fmt.Sprintf("%s:%v", app.Path, app.Connections))
			if strings.EqualFold(app.Path, exe) && app.Connections["a1"] > 0 {
				t.Logf("engine observed %s on line a1 toward %s", exe, fixture.target)
				return true
			}
		}
		return false
	})
	if t.Failed() {
		t.Logf("apps observed: %q", observed)
	}
}

func hostedTestExecutable() string { exe, _ := os.Executable(); return exe }
