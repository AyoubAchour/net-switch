package lifecycle

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/platform"
	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/platform/worker"
)

func nativePlatform(c Config, log func(string)) platform.System {
	return &win.System{Workers: worker.Supervisor{Executable: filepath.Join(c.Directory, "netswitch-engine.exe"), Log: func(err error) { log(err.Error()) }}, EnginePath: c.Adapter, Root: c.Directory, UserDir: c.Data, MachineDir: c.Data}
}
func Worker(args []string) int { return win.Run(args) }
func DesktopCall(ctx context.Context, operation string, args map[string]any) (any, error) {
	switch operation {
	case "app-info", "installed-apps":
		return win.Execute(operation, args)
	case "autostart":
		return desktopAutostart(nil)
	case "autostart-set":
		value, _ := args["on"].(bool)
		return desktopAutostart(&value)
	case "autostart-upgrade":
		return "unchanged", nil
	}
	return nil, fmt.Errorf("desktop operation %q refused", operation)
}
