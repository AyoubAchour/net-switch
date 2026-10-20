package winplatform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// VerifyDirectory authenticates an already provisioned machine store without
// changing its ACLs or moving it. Services call this while another service may
// have live files and a working directory inside the tree. Provisioning uses
// ProtectDirectory, which needs exclusive mutation access.
func VerifyDirectory(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	certificate, err := directoryCertificate(path)
	if err != nil {
		return err
	}
	if certificate == "" {
		return fmt.Errorf("machine store has no installation certificate")
	}
	var rootIdentity string
	markerOK := false
	var walk func(string, bool) error
	walk = func(name string, root bool) error {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_READ_DATA,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		f := os.NewFile(uintptr(h), name)
		defer f.Close()
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			return err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("machine-store reparse point refused: %s", name)
		}
		directory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if !directory && info.NumberOfLinks > 1 {
			return fmt.Errorf("machine-store hard link refused: %s", name)
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		if !trustedMachineSecurity(sd) {
			return fmt.Errorf("machine-store ownership or permissions changed: %s", name)
		}
		if root {
			if !directory {
				return fmt.Errorf("machine store is not a directory")
			}
			rootIdentity = fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
		}
		if !directory {
			if name == filepath.Join(path, directoryMarkerName) {
				b, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
				if err != nil {
					return err
				}
				if len(b) > 4*1024*1024 {
					return fmt.Errorf("machine-store marker exceeds its limit")
				}
				_, markerOK = parseDirectoryMarker(sd, b, rootIdentity, path, certificate)
			}
			return nil
		}
		names, err := f.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, child := range names {
			if err := walk(filepath.Join(name, child), false); err != nil {
				// Atomic file replacement may remove a temporary name between
				// enumeration and open. Other errors must not weaken the check.
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
		}
		return nil
	}
	// Reject reparse ancestors before resolving descendants. Their handles
	// remain pinned against rename throughout this read-only check.
	var held []windows.Handle
	defer func() {
		for _, h := range held {
			windows.CloseHandle(h)
		}
	}()
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		p, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return err
		}
		held = append(held, h)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			return err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("machine-store ancestor is a reparse point")
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	if err := walk(path, true); err != nil {
		return err
	}
	if !markerOK {
		return fmt.Errorf("machine-store identity does not match its installation certificate")
	}
	return nil
}
