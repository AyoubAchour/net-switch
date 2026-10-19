//go:build windows

// Package wintun owns packet sessions for the signed Wintun 0.14.1 driver.
// The DLL manages adapters; no production packet I/O goes through its API.
package wintun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const DefaultGUID = "{D9B44E84-B5C7-4DC4-97A4-4E7CA6722686}"

// Config is also usable by TestISP. A test must use its own name and GUID.
// Address, MTU and route configuration belong to the engine's platform layer.
type Config struct {
	Name       string
	GUID       string
	TunnelType string
	MTU        int
	Capacity   uint32
}

func (c Config) defaults() Config {
	if c.Name == "" {
		c.Name = "NetSwitch"
	}
	if c.GUID == "" {
		c.GUID = DefaultGUID
	}
	if c.TunnelType == "" {
		c.TunnelType = "NetSwitch"
	}
	if c.MTU == 0 {
		c.MTU = 9000
	}
	if c.Capacity == 0 {
		c.Capacity = 0x800000
	}
	return c
}

var pinnedDLL = map[string]string{
	"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
	"arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
}

type library struct {
	module                                  windows.Handle
	file                                    *os.File // Denies replacement/writes for the lifetime of the loaded DLL.
	create, open, close, luid, deleteDriver uintptr
}

type libraryCache struct {
	sync.Mutex
	loaded *library
}

func (c *libraryCache) get(load func() (*library, error)) (*library, error) {
	c.Lock()
	defer c.Unlock()
	if c.loaded != nil {
		return c.loaded, nil
	}
	l, err := load()
	if err == nil {
		c.loaded = l
	}
	return l, err
}

var dllCache libraryCache

func loadLibrary() (*library, error) { return dllCache.get(loadVerifiedLibrary) }

func loadVerifiedLibrary() (*library, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("Wintun beside executable: %w", err)
	}
	if !strings.EqualFold(filepath.Clean(path), resolved) {
		return nil, fmt.Errorf("Wintun DLL must be a regular file beside the executable")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	digest := sha256.New()
	if _, err = io.Copy(digest, f); err != nil {
		return nil, err
	}
	if expected := pinnedDLL[runtime.GOARCH]; expected == "" || fmt.Sprintf("%x", digest.Sum(nil)) != expected {
		return nil, fmt.Errorf("Wintun 0.14.1 SHA-256 mismatch (%s)", runtime.GOARCH)
	}
	// Dependencies may come only from System32, never CWD or PATH.
	module, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	l := &library{module: module, file: f}
	for name, dst := range map[string]*uintptr{
		"WintunCreateAdapter": &l.create, "WintunOpenAdapter": &l.open,
		"WintunCloseAdapter": &l.close, "WintunGetAdapterLUID": &l.luid,
		"WintunDeleteDriver": &l.deleteDriver,
	} {
		*dst, err = windows.GetProcAddress(module, name)
		if err != nil {
			windows.FreeLibrary(module)
			return nil, err
		}
	}
	// Do not unload: the DLL queues asynchronous orphan cleanup callbacks.
	ok = true
	return l, nil
}

type Adapter struct {
	mu                     sync.Mutex
	dll                    *library
	handle                 uintptr
	config                 Config
	luid                   uint64
	instanceID, devicePath string
	session                *Session
}

// Create owns the adapter. Close removes it through the signed DLL, after
// unregistering its session. It never adopts an existing adapter by name.
func Create(config Config) (*Adapter, error) { return adapter(config, true) }

// Open verifies the existing adapter's GUID before permitting a session.
// Its Close releases this reference, not the other process's ownership.
func Open(config Config) (*Adapter, error) { return adapter(config, false) }

func adapter(config Config, create bool) (*Adapter, error) {
	c := config.defaults()
	if !validCapacity(c.Capacity) || c.MTU < 576 || c.MTU > MaxPacketSize {
		return nil, fmt.Errorf("invalid Wintun capacity or MTU")
	}
	guid, err := windows.GUIDFromString(c.GUID)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(c.Name)
	if err != nil {
		return nil, err
	}
	kind, err := windows.UTF16PtrFromString(c.TunnelType)
	if err != nil {
		return nil, err
	}
	l, err := loadLibrary()
	if err != nil {
		return nil, err
	}
	var h uintptr
	var callErr syscall.Errno
	if create {
		h, _, callErr = syscall.SyscallN(l.create, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(kind)), uintptr(unsafe.Pointer(&guid)))
	} else {
		h, _, callErr = syscall.SyscallN(l.open, uintptr(unsafe.Pointer(name)))
	}
	if h == 0 {
		return nil, fmt.Errorf("Wintun adapter %q: %w", c.Name, callErr)
	}
	a := &Adapter{dll: l, handle: h, config: c}
	syscall.SyscallN(l.luid, h, uintptr(unsafe.Pointer(&a.luid)))
	var actual windows.GUID
	ret, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceLuidToGuid").Call(uintptr(unsafe.Pointer(&a.luid)), uintptr(unsafe.Pointer(&actual)))
	if ret != 0 || actual != guid {
		syscall.SyscallN(l.close, h)
		return nil, fmt.Errorf("Wintun adapter identity mismatch: wanted %s, got %s (status %d)", guid.String(), actual.String(), ret)
	}
	a.instanceID, a.devicePath, err = deviceForGUID(guid)
	if err != nil {
		syscall.SyscallN(l.close, h)
		return nil, err
	}
	return a, nil
}

var netClass = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0, 0x2b, 0xe1, 0x03, 0x18}}
var netInterface = windows.GUID{Data1: 0xcac88484, Data2: 0x7515, Data3: 0x4c03, Data4: [8]byte{0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61}}

func deviceForGUID(guid windows.GUID) (string, string, error) {
	set, err := windows.SetupDiGetClassDevsEx(&netClass, "SWD\\Wintun", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return "", "", err
	}
	defer set.Close()
	for i := 0; ; i++ {
		dev, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			break
		}
		if err != nil {
			return "", "", err
		}
		h, err := windows.SetupDiOpenDevRegKey(set, dev, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err != nil {
			continue
		}
		key := registry.Key(h)
		id, _, readErr := key.GetStringValue("NetCfgInstanceId")
		key.Close()
		if readErr != nil || !strings.EqualFold(id, guid.String()) {
			continue
		}
		instance, err := set.DeviceInstanceID(dev)
		if err != nil {
			return "", "", err
		}
		paths, err := windows.CM_Get_Device_Interface_List(instance, &netInterface, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
		if err != nil {
			return "", "", err
		}
		if len(paths) != 1 {
			return "", "", fmt.Errorf("adapter has %d device interfaces", len(paths))
		}
		return instance, paths[0], nil
	}
	return "", "", fmt.Errorf("Wintun device interface for %s: %w", guid.String(), windows.ERROR_NOT_FOUND)
}

func (a *Adapter) LUID() uint64       { return a.luid }
func (a *Adapter) InstanceID() string { return a.instanceID }
func (a *Adapter) MTU() int           { return a.config.MTU }

func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handle == 0 {
		return nil
	}
	var err error
	if a.session != nil {
		err = a.session.Close()
	}
	syscall.SyscallN(a.dll.close, a.handle)
	a.handle = 0
	return err
}

// DeleteDriver is an explicit installer operation. Never call it as session
// cleanup: Wintun is shared with other applications.
func DeleteDriver() error {
	l, err := loadLibrary()
	if err != nil {
		return err
	}
	ok, _, callErr := syscall.SyscallN(l.deleteDriver)
	if ok == 0 {
		return callErr
	}
	return nil
}

// RecoverAfterCrash is called by the service-manager cleanup action under the
// engine's ownership-journal lock, after verifying that the owner has exited.
// Remove only a non-present Wintun device matching that GUID. This deliberately
// does not load or call the DLL: its asynchronous orphan sweep is unscoped.
func RecoverAfterCrash(config Config) error {
	_, err := recoverAfterCrash(config)
	return err
}

func recoverAfterCrash(config Config) (int, error) {
	if config.GUID == "" || config.Name == "" {
		return 0, fmt.Errorf("crash recovery requires the journaled adapter name and GUID")
	}
	guid, err := windows.GUIDFromString(config.GUID)
	if err != nil {
		return 0, err
	}
	set, err := windows.SetupDiGetClassDevsEx(&netClass, "SWD\\Wintun", 0, 0, 0, "")
	if err != nil {
		return 0, err
	}
	defer set.Close()
	for i := 0; ; i++ {
		dev, err := set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, nil // A clean system requires no adapter creation or DLL load.
		}
		if err != nil {
			return 0, err
		}
		h, err := set.OpenDevRegKey(dev, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err != nil {
			continue
		}
		key := registry.Key(h)
		id, _, readErr := key.GetStringValue("NetCfgInstanceId")
		key.Close()
		if readErr != nil || !strings.EqualFold(id, guid.String()) {
			continue
		}
		var status, problem uint32
		err = windows.CM_Get_DevNode_Status(&status, &problem, dev.DevInst, 0)
		if err == nil {
			return 0, fmt.Errorf("refusing crash cleanup of present adapter %s", config.GUID)
		}
		if !errors.Is(err, windows.CR_NO_SUCH_DEVNODE) {
			return 0, fmt.Errorf("check crashed Wintun device: %w", err)
		}
		params := windows.RemoveDeviceParams{ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE), Scope: windows.DI_REMOVEDEVICE_GLOBAL}
		if err := set.SetClassInstallParams(dev, &params.ClassInstallHeader, uint32(unsafe.Sizeof(params))); err != nil {
			return 0, err
		}
		if err := set.CallClassInstaller(windows.DIF_REMOVE, dev); err != nil {
			return 0, fmt.Errorf("remove crashed Wintun device: %w", err)
		}
		return 1, nil
	}
}
