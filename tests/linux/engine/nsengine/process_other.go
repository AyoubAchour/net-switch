//go:build !linux

package nsengine

import (
	"context"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

type engineProcess struct{}

func (d *Driver) launch(context.Context, engine.Env) error {
	return notYet("Linux namespaces unavailable")
}
func (d *Driver) crash() error                   { return notYet("Linux namespaces unavailable") }
func (d *Driver) cleanup(context.Context) error  { return notYet("Linux namespaces unavailable") }
func (d *Driver) waitExit(context.Context) error { return nil }
func (d *Driver) running() bool                  { return false }
func (d *Driver) logPath() string                { return "" }
