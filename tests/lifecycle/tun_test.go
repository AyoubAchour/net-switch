package lifecycle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
	line, target string
	dial         func(context.Context, string, string) (net.Conn, error)
	exchange     func(*testing.T, net.Conn)
	installed    func(*testing.T)
	clean        func(*testing.T)
}

func tunServices(t *testing.T, config lifecycle.Config, owner actor) {
	t.Helper()
	fixture := prepareTUN(t, config.Directory, config.Data)
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
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	for _, failure := range []string{"engine-kill", "lease-expiry"} {
		t.Run(failure, func(t *testing.T) {
			if err := service.Start(ctx, service.Control); err != nil {
				t.Fatal(err)
			}
			c := openClient(t, owner, false)
			defer c.input.Close()
			c.must(t, "signin", nil, nil)
			wait(t, "TUN routing on", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
			conn, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal("captured traffic failed", err)
			}
			defer conn.Close()
			fixture.exchange(t, conn)
			assertTUNCaptured(t, config.Data, getStatus(t, c).Instance, fixture)
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
			kill(t, control.PID)
			fixture.exchange(t, conn) // Control death alone must preserve the flow
			if failure == "engine-kill" {
				kill(t, engine.PID)
			}
			wait(t, "TUN engine stopped", 45*time.Second, func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
			fixture.clean(t)
			direct, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal("previously captured target is not direct after cleanup", err)
			}
			fixture.exchange(t, direct)
			direct.Close()
			t.Log("TUN captured a live stream; adapter/routes/rules returned to baseline; the same target works directly")
		})
	}
}

func assertTUNCaptured(t *testing.T, data, instance string, fixture tunFixture) {
	t.Helper()
	var config struct {
		Experimental struct {
			API struct {
				Address string `json:"external_controller"`
				Secret  string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := lifecycle.Read(filepath.Join(data, "adapter-"+instance, "engine-config.json"), &config); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(fixture.target)
	client := &http.Client{Transport: &http.Transport{DialContext: fixture.dial}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	wait(t, "stream observed inside the TUN adapter", 10*time.Second, func() bool {
		req, _ := http.NewRequest("GET", "http://"+config.Experimental.API.Address+"/connections", nil)
		req.Header.Set("Authorization", "Bearer "+config.Experimental.API.Secret)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result struct {
			Connections []struct {
				Metadata map[string]any `json:"metadata"`
			} `json:"connections"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		for _, flow := range result.Connections {
			m := flow.Metadata
			if fmt.Sprint(m["destinationIP"]) == host && fmt.Sprint(m["destinationPort"]) == port {
				b, _ := json.Marshal(m)
				if !strings.Contains(strings.ToLower(string(b)), "tun") {
					t.Fatal("target was not a TUN inbound", string(b))
				}
				t.Log("adapter observed TUN destination", fixture.target)
				return true
			}
		}
		return false
	})
}

func hostedTestExecutable() string { exe, _ := os.Executable(); return exe }
