package nsengine

import (
	"errors"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// refusals classifies the protocol's refusals. The engine sends a refusal as
// its error text alone (protocol.Reply has no code), so this table is the one
// place that reads text: cases test the typed code, never a message. Where
// the engine's packages export the error, the text comes from that error.
// TestRefusalsMatchTheServer provokes every refusal from a real
// protocol.Server, so a reworded or new refusal fails the build's tests
// instead of turning into a silent mismatch.
var refusals = map[string]engine.RefusalCode{
	"controller fenced":                        engine.RefusedFenced,
	"control lease expired or engine stopping": engine.RefusedLapsed,
	"attach refused":                           engine.RefusedAttach,
	flows.ErrStale.Error():                     engine.RefusedStale,
	flows.ErrConflict.Error():                  engine.RefusedConflict,
	"invalid revision number or hash":          engine.RefusedInvalidRevision,
	"opId conflict":                            engine.RefusedOperationConflict,
	// flows.Selector.Validate and Table.CloseFlows.
	"select exactly one closure condition":                           engine.RefusedSelector,
	"reconnect requires both app and notLine":                        engine.RefusedSelector,
	"outside connections are handled by Control":                     engine.RefusedSelector,
	"shared apps reconnect only outside connections through Control": engine.RefusedSelector,
	flows.ErrBudget.Error():  engine.RefusedCapacity,
	flows.ErrStopped.Error(): engine.RefusedNotRunning,
}

// classify turns an engine error into a refusal when the protocol defines
// it, and a plain failure otherwise.
func classify(message string) error {
	if code, ok := refusals[message]; ok {
		return &engine.Refusal{Code: code, Message: message}
	}
	return errors.New("engine failure: " + message)
}
