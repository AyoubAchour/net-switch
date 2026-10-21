package singbox

import "strings"

// LinuxProcessPath decodes the pinned Clash API's display field. Its Linux
// process lookup appends a parenthesized username (or UID) to an executable
// path. A bare UID is an unresolved executable, not an app path. This adapter
// detail is retired with sing-box; native engine identities are structured.
func LinuxProcessPath(display string) string {
	if !strings.HasPrefix(display, "/") {
		return ""
	}
	if strings.HasSuffix(display, ")") && !strings.HasSuffix(display, " (deleted)") {
		if delimiter := strings.LastIndex(display, " ("); delimiter >= 0 {
			display = display[:delimiter]
		}
	}
	return strings.TrimSuffix(display, " (deleted)")
}
