package lifecycle

import (
	"strings"
	"testing"
)

func TestNativeChildEnvironmentSeparatesHostWatchdogAndMemory(t *testing.T) {
	for _, key := range []string{"NOTIFY_SOCKET", "WATCHDOG_PID", "WATCHDOG_USEC", "LISTEN_PID", "LISTEN_FDS", "GOMEMLIMIT", "GOGC"} {
		t.Setenv(key, "1")
	}
	values := map[string]string{}
	for _, entry := range nativeChildEnvironment() {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	for _, key := range []string{"NOTIFY_SOCKET", "WATCHDOG_PID", "WATCHDOG_USEC", "LISTEN_PID", "LISTEN_FDS", "GOGC"} {
		if _, ok := values[key]; ok {
			t.Fatal("host setting leaked", key)
		}
	}
	if values["GOMEMLIMIT"] != "512MiB" {
		t.Fatal(values["GOMEMLIMIT"])
	}
}
