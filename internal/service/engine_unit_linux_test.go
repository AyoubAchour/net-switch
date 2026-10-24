package service

import (
	"strings"
	"testing"
)

// The host never respawns the native child and the service manager never
// respawns the host: Control owns every engine restart (spec §3.4). Only
// Control's own unit restarts on failure.
func TestEngineUnitNeverRestartsItself(t *testing.T) {
	files := unitFiles(Config{Directory: "/opt/netswitch", Data: "/var/lib/netswitch", Native: true})
	engine := files["netswitch-engine.service"]
	if !strings.Contains(engine, "\nRestart=no\n") || !strings.Contains(engine, "ExecStopPost=") {
		t.Fatal("engine unit must only clean up after a failure, never restart", engine)
	}
	if !strings.Contains(files["netswitch.service"], "\nRestart=on-failure\n") {
		t.Fatal("Control's unit must restart on failure", files["netswitch.service"])
	}
}
