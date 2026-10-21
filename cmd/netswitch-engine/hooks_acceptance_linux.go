//go:build linux && acceptance

package main

import (
	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

func installTestHooks(p *linux.Platform, e *engine.Engine, s *protocol.Server) {
	p.InstallAcceptanceHooks(e, s)
}
