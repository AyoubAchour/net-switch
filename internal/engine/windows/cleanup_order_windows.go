//go:build windows

package winengine

import "os"

// Hosted ordering experiment. The shared journal still validates and inspects
// every record, and retains all intents if any later check fails. Only the
// owned adapter's existing fingerprint-checked removal moves earlier.
func (o object) CleanupPriority() int {
	if o.kind == "adapter" && hostedTraceEnabled() && os.Getenv("NETSWITCH_ENGINE_ADAPTER_FIRST") == "1" {
		return -1
	}
	return 0
}
