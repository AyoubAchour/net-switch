package winplatform

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Legacy Node takes ownership of every file under the machine folder. File
// ownership therefore cannot authenticate a planted migration marker. This
// separate HKLM key is never touched by Node and cannot be created or written
// by a standard user. Values bind a configured path to a fresh ID and creation
// nonce; an old record cannot authenticate a subsequently recycled file ID.
const directoryCertificateKey = `SOFTWARE\NetSwitch.ControlDirectoryCertificates.v1`

func directoryCertificateName(path string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(path))))
}

func openDirectoryCertificates(write bool) (registry.Key, error) {
	access := uint32(registry.QUERY_VALUE | registry.WOW64_64KEY | windows.READ_CONTROL)
	var key registry.Key
	var err error
	if write {
		access |= registry.SET_VALUE
		security, e := windows.SecurityDescriptorFromString("O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)")
		if e != nil {
			return 0, e
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}
		path, e := windows.UTF16PtrFromString(directoryCertificateKey)
		if e != nil {
			return 0, e
		}
		status, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegCreateKeyExW").Call(
			uintptr(registry.LOCAL_MACHINE), uintptr(unsafe.Pointer(path)), 0, 0, 0, uintptr(access),
			uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&key)), 0)
		if status != 0 {
			return 0, windows.Errno(status)
		}
	} else {
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, directoryCertificateKey, access)
		if err != nil {
			return 0, err
		}
	}
	// Never repair an existing weak certificate key in place: that would
	// repeat the retained-handle problem this provenance check prevents.
	sd, err := windows.GetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		control, _, e := sd.Control()
		if e != nil || control&windows.SE_DACL_PROTECTED == 0 || !trustedAdminSecurity(sd, registry.ALL_ACCESS) {
			err = fmt.Errorf("machine-folder certificate key has unexpected ownership or permissions")
		}
	}
	if err != nil {
		key.Close()
		return 0, err
	}
	return key, nil
}

func directoryCertificate(path string) (string, error) {
	key, err := openDirectoryCertificates(false)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	identity, _, err := key.GetStringValue(directoryCertificateName(path))
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return identity, err
}

func certifyDirectory(path, identity string) error {
	key, err := openDirectoryCertificates(true)
	if err != nil {
		return fmt.Errorf("open machine-folder certificate store: %w", err)
	}
	defer key.Close()
	if err := key.SetStringValue(directoryCertificateName(path), identity); err != nil {
		return err
	}
	// Flush only on fresh creation/migration, before quarantine can remove the
	// old root. A process or machine failure can then resume the durable stage.
	status, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey").Call(uintptr(key))
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}
