package lifecycle

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func desktopAutostart(on *bool) (any, error) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	value := windows.ComposeCommandLine([]string{exe, "--background"})
	if on != nil {
		if *on {
			err = key.SetStringValue("NetSwitch", value)
		} else {
			err = key.DeleteValue("NetSwitch")
			if err == registry.ErrNotExist {
				err = nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	current, _, err := key.GetStringValue("NetSwitch")
	if err == registry.ErrNotExist {
		return false, nil
	}
	return current == value, err
}
func ShowPairing(url, code, owner string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	address, _ := windows.UTF16PtrFromString(url)
	if err := windows.ShellExecute(0, verb, address, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return err
	}
	// This window belongs to the enrolled user's process and session.
	message, _ := windows.UTF16PtrFromString("Net Switch is set up for " + owner + ".\n\nEnter this code in your browser:\n\n" + code + "\n\nIt expires in two minutes.")
	title, _ := windows.UTF16PtrFromString("Connect to Net Switch")
	go func() {
		windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x40)
	}()
	return nil
}
func ShowStatus(text string) error {
	message, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return err
	}
	title, _ := windows.UTF16PtrFromString("Net Switch")
	windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x40)
	return nil
}
