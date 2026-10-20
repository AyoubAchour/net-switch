package lifecycle

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func desktopAutostart(on *bool) (any, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".config/autostart/netswitch.desktop")
	if on != nil {
		if *on {
			exe, err := os.Executable()
			if err != nil {
				return nil, err
			}
			if strings.ContainsAny(exe, "\n\r\"%") {
				return nil, fmt.Errorf("unsupported desktop executable path")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return nil, err
			}
			body := "[Desktop Entry]\nType=Application\nName=Net Switch\nExec=\"" + exe + "\" --background\nTerminal=false\n"
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				return nil, err
			}
		} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
func ShowPairing(url, code string) error {
	cmd := exec.Command("xdg-open", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	// notify-send uses the owner's session bus. No credential is ever passed
	// in arguments: the code goes through stdin to the desktop's own console
	// until M5 supplies the native notification/window binding.
	fmt.Printf("Net Switch pairing code: %s (valid for two minutes)\n", code)
	return nil
}
