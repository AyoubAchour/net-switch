package singbox

import "testing"

func TestLinuxClashDisplayPath(t *testing.T) {
	for display, want := range map[string]string{
		"/usr/bin/curl":                "/usr/bin/curl",
		"/opt/app (NSLifecycleOther)":  "/opt/app",
		"/opt/app (1001)":              "/opt/app",
		"/opt/My App (x86)/run (root)": "/opt/My App (x86)/run",
		"/opt/app (directory user)":    "/opt/app",
		"/opt/app (deleted) (runner)":  "/opt/app",
		"/opt/app (deleted)":           "/opt/app",
		"1001":                         "",
		"":                             "",
	} {
		if got := LinuxProcessPath(display); got != want {
			t.Errorf("%q: got %q, want %q", display, got, want)
		}
	}
}
