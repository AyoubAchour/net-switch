package service

import (
	"os"
	"strings"
)

// ChildEnvironment prevents a helper, systemctl or adapter from inheriting the
// parent service's activation descriptors and readiness notification address.
func ChildEnvironment() []string {
	out := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "NOTIFY_SOCKET", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES":
			continue
		}
		out = append(out, entry)
	}
	return out
}
