//go:build windows

package wintun

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/platform/winchild"
)

type RegistrarObserver func(context.Context, winchild.Registrar) error

var supervisedRegistrar atomic.Pointer[RegistrarObserver]

// ConfigureSupervisorChild is for the native child's private bootstrap, before
// any session is created. No command-line/environment option enables it in the
// standalone runtime. The one-process limit refuses ordinary descendants; only
// the registrar explicitly breaks away AND enters its own restricted job in
// the same CreateProcess call. The child alone holds that registrar job handle.
func ConfigureSupervisorChild(observer RegistrarObserver) error {
	if observer == nil {
		return errors.New("supervisor registrar observer is required")
	}
	if err := winchild.CheckRegistrarParent(); err != nil {
		return err
	}
	supervisedRegistrar.Store(&observer)
	return nil
}
