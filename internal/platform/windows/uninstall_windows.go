package winplatform

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// PrepareMachineUninstall recovers a certified stage before the legacy restore
// tool reads the live Undo record. A migration that could not recover Undo
// must not turn into a successful "nothing to undo" followed by deletion.
func PrepareMachineUninstall(path string, log func(string)) error {
	return prepareDirectory(path, log, nil, func(m directoryMarker) error {
		// This provenance survives a successful startup and repeated uninstall
		// attempts. Reading only this invocation's log would lose the warning.
		for _, note := range m.Notes {
			if strings.Contains(note, "WARNING:") || strings.Contains(note, "restored the validated Windows Undo backup") {
				log(note)
				return fmt.Errorf("Undo recovery is uncertain; retaining machine data and migration records")
			}
		}
		return nil
	})
}

func machineCleanupName(name, base string) bool {
	if name == base || name == base+".migrating" {
		return true
	}
	for _, prefix := range []string{base + ".untrusted-", base + ".migrating.untrusted-"} {
		if tail, ok := strings.CutPrefix(name, prefix); ok && len(tail) == 24 {
			_, err := hex.DecodeString(tail)
			return err == nil
		}
	}
	return false
}

// CleanupMachineData runs only after restoration succeeds or the owner elects
// to discard Undo. Each entry is inspected and deleted through the same
// no-follow handle. No ownership, DACL or file attribute is ever rewritten.
func CleanupMachineData(path string, log func(string)) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	open := func(name string, access uint32) (*os.File, windows.ByHandleFileInformation, error) {
		var info windows.ByHandleFileInformation
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, info, err
		}
		h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil, info, err
		}
		f := os.NewFile(uintptr(h), name)
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			f.Close()
			return nil, info, err
		}
		return f, info, nil
	}
	// Pin every ancestor without following links, so a checked pathname
	// cannot be redirected while descendants are enumerated or deleted.
	var ancestors []string
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		ancestors = append(ancestors, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	var parent *os.File
	for i := len(ancestors) - 1; i >= 0; i-- {
		access := uint32(0)
		if i == 0 {
			access = windows.FILE_LIST_DIRECTORY
		}
		f, info, err := open(ancestors[i], access)
		if err != nil {
			return err
		}
		defer f.Close()
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fmt.Errorf("cleanup ancestor is not a plain directory: %s", ancestors[i])
		}
		parent = f
	}
	var problems []error
	var remove func(string) (bool, error)
	remove = func(name string) (bool, error) {
		// FILE_READ_DATA is FILE_LIST_DIRECTORY for directories. Refuse
		// inaccessible objects rather than taking ownership to delete them.
		f, info, err := open(name, windows.READ_CONTROL|windows.DELETE|windows.FILE_READ_DATA)
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("retain %s: %w", name, err)
		}
		defer f.Close()
		h := windows.Handle(f.Fd())
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return false, err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return false, err
		}
		if owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
			log("retained non-admin-owned machine data: " + name)
			return false, nil
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
			// Ownership alone cannot authorize walking an attacker-writable
			// directory. Retained write handles also conflict with this open.
			if !trustedMachineSecurity(sd) {
				log("retained machine directory with untrusted permissions: " + name)
				return false, nil
			}
			names, err := f.Readdirnames(-1)
			if err != nil {
				return false, err
			}
			empty := true
			for _, child := range names {
				removed, err := remove(filepath.Join(name, child))
				if err != nil {
					problems = append(problems, err)
					log(err.Error())
				}
				empty = empty && removed
			}
			if !empty {
				return false, nil
			}
		}
		// FileDispositionInfo operates on the opened link itself. In
		// particular, never clear a hardlinked file's read-only attribute.
		disposition := byte(1)
		if err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1); err != nil {
			return false, fmt.Errorf("retain %s: safe deletion failed: %w", name, err)
		}
		log("removed machine data: " + name)
		return true, nil
	}
	names, err := parent.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if machineCleanupName(name, filepath.Base(path)) {
			if _, err := remove(filepath.Join(filepath.Dir(path), name)); err != nil {
				problems = append(problems, err)
				log(err.Error())
			}
		}
	}
	key, err := openDirectoryCertificates(true)
	if err != nil {
		return err
	}
	err = key.DeleteValue(directoryCertificateName(path))
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		key.Close()
		return err
	}
	info, err := key.Stat()
	key.Close()
	if err != nil {
		return err
	}
	// Other explicitly configured machine-data folders share this key.
	if info.ValueCount == 0 && info.SubKeyCount == 0 {
		software, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE|registry.WOW64_64KEY)
		if err != nil {
			return err
		}
		defer software.Close()
		if err := registry.DeleteKey(software, strings.TrimPrefix(directoryCertificateKey, `SOFTWARE\`)); err != nil {
			return err
		}
		log("removed machine-folder certification key")
	} else {
		log("removed machine-folder certificate; other configured folders retained their certificates")
	}
	return errors.Join(problems...)
}
