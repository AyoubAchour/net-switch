//go:build windows && !acceptance && !netswitch_handlecheck

package winengine

import (
	"context"
	"errors"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProductNoProcessDiagnostics(t *testing.T) {
	for _, name := range []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "NETSWITCH_ENGINE_TEST_TRACE"} {
		value := "1"
		if name == "GITHUB_ACTIONS" {
			value = "true"
		}
		if name == "RUNNER_ENVIRONMENT" {
			value = "github-hosted"
		}
		t.Setenv(name, value)
	}
	if diagnosticProcesses || hostedTraceEnabled() {
		t.Fatal("product enabled process-based tracing")
	}
	p := newPortDiagnostics()
	defer p.close()
	p.observe(windows.WSAENOBUFS)
	if p.count.Load() != 1 || p.stats()["configurationStatus"] != "disabled" {
		t.Fatal("native refusal counter or disabled state lost", p.stats())
	}
	if r := runNetsh(context.Background(), "interface", "ipv4", "show", "dynamicport", "udp"); r.Error != errDiagnosticProcessesDisabled.Error() {
		t.Fatal(r)
	}
	if config, err := readPortConfiguration(context.Background()); config != nil || !errors.Is(err, errDiagnosticProcessesDisabled) {
		t.Fatal("product enabled the TCP configuration worker", config, err)
	}
	// Inspect the compiled product's source set, so an unconditional process
	// runner cannot be hidden behind a flag that the mocks alone would accept.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	product := build.Default
	product.BuildTags = nil
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		match, err := product.MatchFile(".", name)
		if err != nil {
			t.Fatal(err)
		}
		if !match {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path == "os/exec" || path == "github.com/AyoubAchour/net-switch/internal/platform/worker" {
				t.Fatal("product engine compiled a subprocess diagnostic", name, path)
			}
		}
	}
}
