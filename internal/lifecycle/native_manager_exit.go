package lifecycle

import (
	"log"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func captureSystemdExit(out *host.Outcome, getenv func(string) string) {
	result := getenv("SERVICE_RESULT")
	if result == "" {
		return // explicit Ctl cleanup must preserve an earlier manager result
	}
	invocation := getenv("INVOCATION_ID")
	exit := host.SystemdExit{Code: getenv("EXIT_CODE"), Status: getenv("EXIT_STATUS"), Result: result}
	// A failed startup may leave the preceding instance's record behind. Do
	// not attribute this invocation's exit to it or retain its old clean exit.
	out.Systemd = nil
	matched := host.ValidInvocationID(invocation) && invocation == out.InvocationID && exit.Valid()
	if matched {
		out.Systemd = &exit
	}
	log.Printf("native manager exit instance=%s invocation=%q matched=%t code=%q status=%q result=%q", out.Instance, invocation, matched, exit.Code, exit.Status, exit.Result)
}
