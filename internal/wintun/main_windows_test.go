//go:build windows

package wintun

import (
	"os"
	"testing"
)

// registrarFixtureMode runs the production registrar's validation, reply and
// lifecycle with no device, so close-ordering tests need no adapter.
const registrarFixtureMode = "__netswitch-wintun-registrar-fixture"

func TestMain(m *testing.M) {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case RegistrarMode:
			os.Exit(RunRegistrar())
		case registrarFixtureMode:
			os.Exit(runRegistrar(func(string, *registration) error { return nil }))
		}
	}
	os.Exit(m.Run())
}
