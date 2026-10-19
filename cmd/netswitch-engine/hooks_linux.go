//go:build linux && !acceptance

package main

import (
	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

func installTestHooks(*linux.Platform, *engine.Engine, *protocol.Server) {}
