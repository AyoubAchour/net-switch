//go:build windows

package wintun

import (
	"fmt"
	"os"
	"testing"
)

// Metadata proves actual process/adapter/session boundaries without imposing
// a reset, a GC, a driver unload or a warm-up between the normal job phases.
func integrityReportContext(t *testing.T, value any) {
	if fields, ok := value.(map[string]any); ok {
		fields["process_id"] = os.Getpid()
		fields["test_path"] = t.Name()
		fields["scenario"] = os.Getenv("NETSWITCH_WINTUN_INTEGRITY_SCENARIO")
		fields["phase"] = os.Getenv("NETSWITCH_WINTUN_INTEGRITY_PHASE")
		fields["repeat"] = os.Getenv("NETSWITCH_WINTUN_INTEGRITY_REPEAT")
		fields["shard"] = os.Getenv("INTEGRITY_SHARD")
	}
}

func integrityAdapterState(t *testing.T, a *Adapter, event string, err error) {
	if !integrityHooksEnabled || os.Getenv("NETSWITCH_WINTUN_INTEGRITY_TRACE") != "1" {
		return
	}
	report(t, map[string]any{"test": "integrity_adapter", "event": event,
		"adapter_guid": a.config.GUID, "instance": a.InstanceID(), "error": fmt.Sprint(err)})
}

func integrityFixtureState(t *testing.T, f *fixture, mode, event string, err error) {
	if !integrityHooksEnabled || os.Getenv("NETSWITCH_WINTUN_INTEGRITY_TRACE") != "1" {
		return
	}
	// Called before starting the pumps or after joining them. Stats already
	// takes the session lock for ring cursors/registrar ownership. The signed
	// DLL has counters only; its API does not expose internal ring cursors.
	stats, batches := performanceCounters(f.io)
	report(t, map[string]any{"test": "integrity_session", "event": event,
		"adapter_guid": f.a.config.GUID, "session": fmt.Sprintf("%p", f.io),
		"mode": mode, "stats": stats, "write_batches": batches, "error": fmt.Sprint(err)})
}
