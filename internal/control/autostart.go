package control

import (
	"context"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func (c *Core) RefreshAutostart(ctx context.Context) {
	if !c.op.AutostartAllowed {
		return
	}
	v, err := c.op.Platform.Call(ctx, "autostart", nil)
	if err != nil {
		c.log("could not read whether Net Switch starts with Windows: %v", err)
		return
	}
	c.mu.Lock()
	c.autostart = v
	elevated := c.elevated
	c.mu.Unlock()
	if v == true && elevated {
		c.op.Background(func() {
			result, err := c.op.Platform.Call(c.ctx, "autostart-upgrade", nil)
			if err != nil {
				c.log("could not check the startup task: %v", err)
				return
			}
			switch js.Text(result) {
			case "updated":
				c.log("updated the startup task to start the server without a window")
			case "unknown":
				c.log("the startup task runs something unexpected; left it as it is")
			}
		})
	}
}
