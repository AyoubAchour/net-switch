package winplatform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectDirectory inspects the entire original tree before changing security.
// Untrusted owners or grants require new objects: changing an old object's DACL
// cannot revoke a previously opened WRITE_DAC handle. A currently admin-only
// tree is trusted existing data, not evidence about historical permissions.
// The caller must hold the single-instance lock before allowing quarantine.
func ProtectDirectory(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var held []*os.File
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i].Close()
		}
	}()
	type object struct {
		file      *os.File
		directory bool
	}
	open := func(name string, access uint32, share uint32) (object, error) {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return object{}, err
		}
		h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return object{}, fmt.Errorf("open protected path %s (refusing existing writers or renames): %w", name, err)
		}
		// This wrapper owns the handle, including enumeration and closing. A
		// path-based walk would reopen it without sharing our DELETE access.
		file := os.NewFile(uintptr(h), name)
		held = append(held, file)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			return object{}, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return object{}, fmt.Errorf("%s is a reparse point, which Net Switch will not follow", name)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks > 1 {
			return object{}, fmt.Errorf("%s has multiple hard links, which Net Switch will not change", name)
		}
		return object{file: file, directory: info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0}, nil
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
	final, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.FILE_READ_DATA)
	empty, err := windows.SecurityDescriptorFromString("O:BAD:")
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 4; attempt++ {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: final}
		if err := windows.CreateDirectory(p, &attrs); err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return fmt.Errorf("create protected machine folder: %w", err)
		}
		root, err := open(path, access, windows.FILE_SHARE_READ)
		if err != nil {
			return err
		}
		if !root.directory {
			return fmt.Errorf("machine folder %s is not a directory", path)
		}
		var tree []object
		trusted := true
		var inspect func(object) error
		inspect = func(item object) error {
			tree = append(tree, item)
			sd, err := windows.GetSecurityInfo(windows.Handle(item.file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				return fmt.Errorf("inspect security of %s: %w", item.file.Name(), err)
			}
			trusted = trustedMachineSecurity(sd) && trusted
			if !item.directory {
				return nil
			}
			names, err := item.file.Readdirnames(-1)
			if err != nil {
				return fmt.Errorf("enumerate protected folder: %w", err)
			}
			for _, name := range names {
				child, err := open(filepath.Join(item.file.Name(), name), access, windows.FILE_SHARE_READ)
				if err != nil {
					return err
				}
				if err := inspect(child); err != nil {
					return err
				}
			}
			return nil
		}
		if err := inspect(root); err != nil {
			return err
		}
		if trusted {
			// Only now is inheritance safe: no linked outside object or original
			// untrusted grant remains to be hidden by an ACL rewrite.
			for i, item := range tree {
				desired := empty
				if i == 0 {
					desired = final
				}
				if err := setDirectorySecurity(windows.Handle(item.file.Fd()), desired, i == 0); err != nil {
					return fmt.Errorf("protect %s: %w", item.file.Name(), err)
				}
			}
			return nil
		}
		// Descendant handles can prevent a directory rename. They are no longer
		// needed: none of these objects will be trusted or have its ACL changed.
		for i := len(tree) - 1; i > 0; i-- {
			tree[i].file.Close()
		}
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		if err := renameDirectoryHandle(windows.Handle(root.file.Fd()), path+".untrusted-"+hex.EncodeToString(nonce[:])); err != nil {
			return fmt.Errorf("move untrusted machine folder aside: %w", err)
		}
	}
	return fmt.Errorf("machine folder was repeatedly replaced while securing it")
}

const fileDeleteChild = 0x00000040 // FILE_DELETE_CHILD (winnt.h)

func trustedMachineSecurity(sd *windows.SECURITY_DESCRIPTOR) bool {
	trustedSID := func(sid *windows.SID) bool {
		return sid != nil && (sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedSID(owner) {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false
	}
	const dangerous = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.MAXIMUM_ALLOWED |
		windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny never makes an existing allow safe: a retained handle could
			// have been opened before that deny was added.
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Mask&dangerous != 0 && !trustedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
				return false
			}
		default:
			// Conditional/object/callback ACEs have different SID layouts.
			// Unknown permission forms are not a basis for trusting old data.
			return false
		}
	}
	return true
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
