package control

import (
	"fmt"
	"path/filepath"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

// PublishSession retains launch.ps1 and the C# tray's token handoff. It is a
// replace-in-place file, never a credential in process arguments.
func (c *Core) PublishSession(port int, token string, pid int) (string, error) {
	session := struct {
		Port      int    `json:"port"`
		Token     string `json:"token"`
		PID       int    `json:"pid"`
		Mode      string `json:"mode"`
		StartedAt string `json:"startedAt"`
	}{port, token, pid, c.op.Mode, c.op.Clock.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
	b, err := js.Marshal(session)
	if err != nil {
		return "", err
	}
	if err := settings.AtomicWrite(filepath.Join(c.op.UserDir, "server.json"), b, c.op.IO); err != nil {
		return "", err
	}
	c.Announce(port)
	return fmt.Sprintf("Net Switch is running at http://127.0.0.1:%d/#token=%s", port, token), nil
}
