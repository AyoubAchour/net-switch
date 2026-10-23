//go:build windows

package wintun

import (
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/platform/winchild"
)

var supervisedRegistrar atomic.Bool

// ConfigureSupervisorChild is for the native child's private bootstrap, before
// any session is created. No command-line/environment option enables it in the
// standalone runtime. Ordinary descendants remain in the supervisor job; only
// the registrar explicitly breaks away AND enters its own restricted job in
// the same CreateProcess call. The child alone holds that registrar job handle.
func ConfigureSupervisorChild() error {
	if err := winchild.CheckRegistrarParent(); err != nil {
		return err
	}
	supervisedRegistrar.Store(true)
	return nil
}
