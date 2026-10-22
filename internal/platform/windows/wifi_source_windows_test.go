package winplatform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The privacy fallback is deliberately stronger than banning opcode 7:
// The 1.0 Windows reader package must have no Native Wi-Fi entry point at all.
// Include build-constrained files, not the frozen 0.3.x helper.
func TestSSIDNoLocationAPIs(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, entry := range entries {
		path := filepath.Join(".", entry.Name())
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		files++
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if symbol := locationAPISymbol(body); symbol != "" {
			t.Errorf("%s imports or resolves location API %q", path, symbol)
		}
	}
	if files < 10 {
		t.Fatalf("source guard visited only %d files", files)
	}
	t.Logf("checked %d production files; no Native Wi-Fi/location API symbols", files)
}

func locationAPISymbol(body []byte) string {
	f, err := parser.ParseFile(token.NewFileSet(), "source.go", body, 0)
	if err != nil {
		return "invalid Go source"
	}
	blocked := ""
	ast.Inspect(f, func(n ast.Node) bool {
		value := ""
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				value, _ = strconv.Unquote(n.Value)
			}
		case *ast.Ident:
			value = n.Name
		}
		lower := strings.ToLower(value)
		for _, name := range []string{"wlanapi", "wlanqueryinterface", "wlangetavailablenetworklist", "wlangetnetworkbsslist", "wlanscan", "getlanidentifiers", "windows.devices.wifi", "windows.devices.geolocation"} {
			if strings.Contains(lower, name) {
				blocked = value
				return false
			}
		}
		return blocked == ""
	})
	return blocked
}

func TestSSIDLocationGuardRejectsOldAPI(t *testing.T) {
	for _, source := range []string{
		`package p; var dll = "wlanapi.dll"`,
		`package p; var proc = "WlanQueryInterface"`,
		`package p; func f() { WlanQueryInterface(7) }`,
		`package p; var proc = "GetLanIdentifiers"`,
	} {
		if locationAPISymbol([]byte(source)) == "" {
			t.Fatalf("guard accepted %s", source)
		}
	}
	if symbol := locationAPISymbol([]byte(`package p; var class = "Windows.Networking.Connectivity.NetworkInformation"`)); symbol != "" {
		t.Fatalf("safe source rejected: %s", symbol)
	}
}
