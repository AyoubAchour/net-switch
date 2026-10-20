package singbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

func TestFrozenWindowsGoldenHashes(t *testing.T) {
	b, err := os.ReadFile("../../../test/fixtures/windows-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var gold map[string]json.RawMessage
	if err = json.Unmarshal(b, &gold); err != nil {
		t.Fatal(err)
	}
	items := []lines.Line{{ID: "aa", Alias: "Ethernet"}, {ID: "bb", Alias: "Wi-Fi"}, {ID: "cc", Alias: "Phone"}}
	check := func(name string, b []byte, want string) {
		t.Helper()
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s: SHA-256 %x != %s\n%s", name, sum, want, b)
		}
	}
	for count := 1; count <= 3; count++ {
		for _, mode := range []string{"tun", "proxy"} {
			for _, ipv6 := range []bool{false, true} {
				name := fmt.Sprintf("%d-%s-ipv6-%t", count, mode, ipv6)
				t.Run(name, func(t *testing.T) {
					b, err := ConfigBytes(ConfigOptions{mode, items[:count], 12345, "golden-secret", 12346, "", ipv6})
					if err != nil {
						t.Fatal(err)
					}
					var want string
					if err := json.Unmarshal(gold[name], &want); err != nil {
						t.Fatal(err)
					}
					check(name, b, want)
				})
			}
		}
		for _, combine := range []bool{false, true} {
			name := fmt.Sprintf("%d-lines-pinned", count)
			if combine {
				name = fmt.Sprintf("%d-lines-combined", count)
			}
			t.Run(name, func(t *testing.T) {
				shares := []lines.Shares{{{ID: "aa", Value: 1}}, {{ID: "aa", Value: .6}, {ID: "bb", Value: .4}}, {{ID: "aa", Value: .5}, {ID: "bb", Value: .3}, {ID: "cc", Value: .2}}}[count-1]
				p := engine.Policy{Lines: items[:count], Combine: combine, Shares: shares, Blocked: []string{items[count-1].ID}, AppLines: apps.Pins{
					{Path: `C:\Apps\app-1.2.3\Browser.exe`, LineID: "aa"}, {Path: `C:\Games\game.exe`, LineID: "bb"}, {Path: `C:\Program Files\WindowsApps\Example_1.2.3_x64__publisher\App.exe`, LineID: "cc"},
				}}
				files, err := RuleFiles(p)
				if err != nil {
					t.Fatal(err)
				}
				var want map[string]string
				if err := json.Unmarshal(gold[name], &want); err != nil {
					t.Fatal(err)
				}
				if len(files) != len(want) {
					t.Fatal("wrong number of rule files")
				}
				for _, f := range files {
					check(name+"/"+f.Tag, f.Bytes, want[f.Tag])
				}
			})
		}
	}
	t.Run("empty-apps", func(t *testing.T) {
		files, err := RuleFiles(engine.Policy{Lines: items})
		if err != nil {
			t.Fatal(err)
		}
		var want map[string]string
		if err := json.Unmarshal(gold["empty-apps"], &want); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			check(f.Tag, f.Bytes, want[f.Tag])
		}
	})
}
