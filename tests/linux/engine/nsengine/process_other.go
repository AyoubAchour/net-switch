//go:build !linux

package nsengine

import (
	"context"
	"fmt"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

type engineProcess struct{}

func unsupported() error {
	return fmt.Errorf("Linux network namespaces are unavailable on this platform: %w", engine.ErrNotImplemented)
}

func (d *Driver) launch(context.Context, engine.Env) error {
	return unsupported()
}
func (d *Driver) crash() error                   { return unsupported() }
func (d *Driver) cleanup(context.Context) error  { return unsupported() }
func (d *Driver) waitExit(context.Context) error { return nil }
func (d *Driver) running() bool                  { return false }
func (d *Driver) logPath() string                { return "" }
