package host

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// SystemdExit contains the manager's ExecStopPost environment, not a result
// inferred from a terminal message or successful cleanup. Signals stay signals.
type SystemdExit struct {
	Code   string `json:"code"`
	Status string `json:"status"`
	Result string `json:"result"`
}

func ValidInvocationID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && id != strings.Repeat("0", 32)
}

func (e SystemdExit) ExitCode() (uint32, bool) {
	if e.Code != "exited" {
		return 0, false
	}
	n, err := strconv.ParseUint(e.Status, 10, 8)
	return uint32(n), err == nil && strconv.FormatUint(n, 10) == e.Status
}

func (e SystemdExit) Valid() bool {
	if len(e.Result) == 0 || len(e.Result) > 64 || strings.Trim(e.Result, "abcdefghijklmnopqrstuvwxyz-") != "" {
		return false
	}
	switch e.Code {
	case "": // systemd could not start/identify the main process
		return e.Status == ""
	case "exited":
		_, known := e.ExitCode()
		return known
	case "killed", "dumped":
		return len(e.Status) > 0 && len(e.Status) <= 32 && strings.Trim(e.Status, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-") == ""
	default:
		return false
	}
}
