package lifecycle_test

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/service"
	"golang.org/x/sys/windows/svc/mgr"
)

// The host never respawns its child and SCM never respawns the host: the
// Engine service's only failure action is the recovery command (spec §3.4).
func assertEngineHasNoManagerRestart(t *testing.T) {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(service.Engine)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	actions, err := s.RecoveryActions()
	if err != nil {
		t.Fatal(err)
	}
	command := false
	for _, a := range actions {
		if a.Type == mgr.ServiceRestart || a.Type == mgr.ComputerReboot {
			t.Fatalf("engine service has a manager restart action: %+v", actions)
		}
		command = command || a.Type == mgr.RunCommand
	}
	if !command {
		t.Fatalf("engine service has no recovery command: %+v", actions)
	}
	t.Logf("NATIVE_CONTROL_RECOVERY_ACTIONS engine=%+v", actions)
}
