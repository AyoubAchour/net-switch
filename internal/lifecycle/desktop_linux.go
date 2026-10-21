package lifecycle

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
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
func ShowPairing(url, code, owner string) error {
	if err := notify("Connect to Net Switch", "Net Switch is set up for "+owner+". Enter "+code+" in your browser. This code expires in two minutes."); err != nil {
		return err
	}
	cmd := exec.Command("xdg-open", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
func ShowStatus(message string) error { return notify("Net Switch", message) }
func notify(title, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bus, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("the owner session's notification service is unavailable: %w", err)
	}
	defer bus.Close()
	var id uint32
	err = bus.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications").
		CallWithContext(ctx, "org.freedesktop.Notifications.Notify", 0, "Net Switch", uint32(0), "network-workgroup",
			title, message,
			[]string{}, map[string]dbus.Variant{"transient": dbus.MakeVariant(true)}, int32(120000)).Store(&id)
	if err != nil {
		return fmt.Errorf("show pairing code in the owner's session: %w", err)
	}
	return nil
}
