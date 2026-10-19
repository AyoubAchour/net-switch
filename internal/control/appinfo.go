package control

import (
	"context"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/apps"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func (c *Core) lookupInfo(paths []string) {
	c.mu.Lock()
	if c.infoRunning {
		c.mu.Unlock()
		return
	}
	batch := []string{}
	for _, path := range paths {
		key := strings.ToLower(path)
		if path != "" && !c.infoAttempted[key] {
			c.infoAttempted[key] = true
			batch = append(batch, path)
			if len(batch) == 25 {
				break
			}
		}
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
		defer c.mu.Unlock()
		c.infoRunning = false
		if err != nil {
			c.log("could not read app names and icons: %v", err)
			return
		}
		for _, v := range array(result) {
			item := js.Object(v)
			path := js.Text(item["path"])
			if path != "" {
				c.info[apps.AppKey(path)] = item
			}
		}
	})
}
func (c *Core) InstalledApps(ctx context.Context) (any, error) {
	v, err := c.op.Platform.Call(ctx, "installed-apps", nil)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	c.mu.Lock()
	for _, v := range array(v) {
		item := js.Object(v)
		path := js.Text(item["path"])
		paths = append(paths, path)
		item["hasIcon"] = c.info[apps.AppKey(path)]["icon"] != nil
	}
	c.mu.Unlock()
	c.lookupInfo(paths)
	return v, nil
}
