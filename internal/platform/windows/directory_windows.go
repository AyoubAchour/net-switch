package winplatform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectDirectory locks names against replacement and changes security through
// those same handles. An untrusted owner gets a fresh directory, never an ACL
// upgrade over files supplied by that owner. Preopened write handles fail closed.
func ProtectDirectory(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var held []windows.Handle
	defer func() {
		for _, h := range held {
			windows.CloseHandle(h)
		}
	}()
	open := func(name string, access uint32, share uint32) (windows.Handle, error) {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return 0, err
		}
		h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return 0, fmt.Errorf("open protected path %s: %w", name, err)
		}
		held = append(held, h)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			return 0, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return 0, fmt.Errorf("%s is a reparse point, which Net Switch will not follow", name)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks > 1 {
			return 0, fmt.Errorf("%s has multiple hard links, which Net Switch will not change", name)
		}
		return h, nil
	}
	parents := []string{}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		parents = append(parents, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(parents) - 1; i >= 0; i-- {
		if _, err := open(parents[i], 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE); err != nil {
			return err
		}
	}
	// The first DACL is deliberately non-inheritable. Inheritable ACEs would
	// change a hardlinked outside file before the child walk can reject it.
	sealed, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	final, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE)
	var root windows.Handle
	for attempt := 0; attempt < 4; attempt++ {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: final}
		if err := windows.CreateDirectory(p, &attrs); err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return fmt.Errorf("create protected machine folder: %w", err)
		}
		h, err := open(path, access, windows.FILE_SHARE_READ)
		if err != nil {
			return err
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
			root = h
			break
		}
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		if err := renameDirectoryHandle(h, path+".untrusted-"+hex.EncodeToString(nonce[:])); err != nil {
			return fmt.Errorf("move untrusted machine folder aside: %w", err)
		}
	}
	if root == 0 {
		return fmt.Errorf("machine folder was repeatedly replaced while securing it")
	}
	if err := setDirectorySecurity(root, sealed, true); err != nil {
		return err
	}
	var children []windows.Handle
	if err := filepath.WalkDir(path, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == path {
			return nil
		}
		h, err := open(name, access, windows.FILE_SHARE_READ)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if err := setDirectorySecurity(h, sealed, true); err != nil {
				return err
			}
		}
		children = append(children, h)
		return nil
	}); err != nil {
		return err
	}
	if err := setDirectorySecurity(root, final, true); err != nil {
		return err
	}
	empty, err := windows.SecurityDescriptorFromString("O:BAD:")
	if err != nil {
		return err
	}
	for _, child := range children {
		// Parent-before-child order restores the legacy inherited ACLs.
		if err := setDirectorySecurity(child, empty, false); err != nil {
			return err
		}
	}
	return nil
}

func setDirectorySecurity(h windows.Handle, desired *windows.SECURITY_DESCRIPTOR, protected bool) error {
	owner, _, err := desired.Owner()
	if err != nil {
		return err
	}
	acl, _, err := desired.DACL()
	if err != nil {
		return err
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		flags = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, flags, owner, nil, acl, nil); err != nil {
		return err
	}
	actual, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	actualOwner, _, err := actual.Owner()
	if err != nil || !actualOwner.Equals(owner) {
		return fmt.Errorf("machine folder owner did not persist: %v", err)
	}
	// GetSecurityInfo may include the auto-inherited control flag. Compare
	// protected descriptors without that informational flag.
	if protected && strings.ReplaceAll(actual.String(), "D:PAI", "D:P") != desired.String() {
		return fmt.Errorf("machine folder ACL did not persist: %s", actual.String())
	}
	actualACL, _, err := actual.DACL()
	if err != nil || actualACL == nil || actualACL.AceCount != 2 {
		return fmt.Errorf("unexpected machine folder access list: %s", actual.String())
	}
	seen := map[string]bool{}
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(actualACL, i, &ace); err != nil {
			return err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != 0x1f01ff ||
			!(sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
			return fmt.Errorf("unexpected machine folder grant: %s", actual.String())
		}
		seen[sid.String()] = true
	}
	if len(seen) != 2 {
		return fmt.Errorf("machine folder grants are incomplete")
	}
	return nil
}

func renameDirectoryHandle(h windows.Handle, destination string) error {
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	type renameInfo struct {
		Replace uint32
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	var layout renameInfo
	offset := int(unsafe.Offsetof(layout.Name))
	b := make([]byte, offset+len(name)*2)
	info := (*renameInfo)(unsafe.Pointer(&b[0]))
	info.Length = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.Name[0], len(name)), name)
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &b[0], uint32(len(b)))
}
