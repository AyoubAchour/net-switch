// Package host supplies the small boundary shared by standalone native engines
// and their service hosts. It does not select an engine or start a process.
package host

import (
	"context"
	"crypto/tls"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"io"
)

type Listener interface {
	Accept(context.Context) (io.ReadWriteCloser, error)
	Close() error
}

type State interface {
	flows.StateStore
	InitialEpoch() uint64
	SaveEpoch(uint64) error
}

type Options struct {
	// Listen replaces only the transport. The child retains all protocol state.
	Listen func() (Listener, error)
	// HealthKey enables the private, TUN-bound forwarding endpoint for a child.
	// It is delivered over inherited capabilities, never the public protocol.
	HealthKey []byte
	// OpenState runs only after the native lifetime lock has been acquired.
	OpenState func(instance string) (State, error)
	// Ready runs after the authenticated listener and its workers exist.
	Ready func(*protocol.Server)
	// Progress is a coarse startup diagnostic, never a packet-path callback.
	Progress func(string)
	// Configure is nil outside hosted fault builds.
	Configure func(*protocol.Server, *flows.Table)
	// WrapTun is nil in product builds; hosted tests stall the actual packet
	// reader without suspending the separate control/lease goroutines.
	WrapTun func(platform.TunDevice) platform.TunDevice
	// RetirementError injects a cached session-close failure in hosted proofs.
	// It is nil in product builds and is never installed by manager recovery.
	RetirementError func() error
	// ProbeTLS is set only by hosted fault builds with a private fixture CA.
	ProbeTLS   *tls.Config
	ProbeError func() error // hosted dial-stage exhaustion injection; nil in product
}

func (o Options) Stage(name string) {
	if o.Progress != nil {
		o.Progress(name)
	}
}
