package control

import (
	"context"
	"fmt"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/apps"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

// DesktopConnected reopens failed display-only reads after the owner's session
// returns. Routing never depends on the availability of shell metadata.
func (c *Core) DesktopConnected() {
	c.installedMu.Lock()
	c.installedCached = nil
	c.installedExpires = 0
	c.installedMu.Unlock()
	c.mu.Lock()
	c.infoAttempted = map[string]bool{}
	c.mu.Unlock()
	if c.op.AutostartAllowed {
		c.op.Background(func() { c.RefreshAutostart(c.ctx) })
	}
}

func (c *Core) lookupInfo(paths []string) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.queueInfoLocked(paths)
	if c.infoRunning {
		c.mu.Unlock()
		return
	}
	count := min(25, len(c.infoPending))
	batch := append([]string{}, c.infoPending[:count]...)
	c.infoPending = c.infoPending[count:]
	for _, path := range batch {
		key := strings.ToLower(path)
		c.infoAttempted[key] = true
		delete(c.infoQueued, key)
	}
	if len(batch) == 0 {
		c.mu.Unlock()
		return
	}
	c.infoRunning = true
	c.mu.Unlock()
	c.op.Background(func() {
		result, err := c.op.Platform.Call(c.ctx, "app-info", map[string]any{"paths": batch})
		c.mu.Lock()
		c.infoRunning = false
		if err != nil {
			c.mu.Unlock()
			c.log("could not read app names and icons: %v", err)
			c.lookupInfo(nil)
			return
		}
		for _, v := range array(result) {
			item := js.Object(v)
			path := js.Text(item["path"])
			if path != "" {
				c.info[apps.AppKey(path)] = item
			}
		}
		c.mu.Unlock()
		c.lookupInfo(nil)
	})
}
func (c *Core) queueInfoLocked(paths []string) {
	for _, path := range paths {
		key := strings.ToLower(path)
		app := apps.AppKey(path)
		if path == "" || strings.EqualFold(baseName(path), "svchost") || c.infoAttempted[key] || c.infoQueued[key] || js.Truth(c.info[app]["icon"]) {
			continue
		}
		c.infoPending = append(c.infoPending, path)
		c.infoQueued[key] = true
	}
}
func (c *Core) InstalledApps(ctx context.Context) (any, error) {
	c.installedMu.Lock()
	if c.installedCached == nil || c.now() >= c.installedExpires {
		v, err := c.op.Platform.Call(ctx, "installed-apps", nil)
		if err != nil {
			c.installedMu.Unlock()
			return nil, err
		}
		list, ok := v.([]any)
		if !ok {
			c.installedMu.Unlock()
			return nil, fmt.Errorf("the installed-app worker returned no list")
		}
		c.installedCached = list
		c.installedExpires = c.now() + 5*60000
	}
	b, err := js.Marshal(c.installedCached)
	c.installedMu.Unlock()
	if err != nil {
		return nil, err
	}
	v, err := js.Decode(b)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	c.mu.Lock()
	for _, v := range array(v) {
		item := js.Object(v)
		path := js.Text(item["path"])
		paths = append(paths, path)
		item["hasIcon"] = js.Truth(c.info[apps.AppKey(path)]["icon"])
	}
	c.mu.Unlock()
	c.lookupInfo(paths)
	return v, nil
}
