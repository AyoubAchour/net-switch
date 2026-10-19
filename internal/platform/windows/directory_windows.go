package winplatform

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/windowsundo"
	"golang.org/x/sys/windows"
)

const directoryMarkerName = ".control-directory-v1"

type directoryMarker struct {
	Identity, Target, Previous, Quarantine string
	Notes                                  []string
}

// ProtectDirectory migrates legacy trees even when their current ACL looks
// safe: tightening a DACL cannot revoke an old WRITE_DAC handle. Only a marker
// owned by Administrators, bound to this fresh directory's identity, permits
// reuse. The caller holds the single-instance lock throughout migration.
func ProtectDirectory(path string) error {
	return protectDirectory(path, func(s string) { fmt.Fprintln(os.Stderr, s) }, nil)
}

func protectDirectory(path string, log func(string), checkpoint func(string) error) error {
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
		identity  string
	}
	open := func(name string, access uint32, share uint32) (object, error) {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return object{}, err
		}
		h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			if err == windows.ERROR_SHARING_VIOLATION {
				return object{}, fmt.Errorf("open protected path %s: an existing handle prevents exclusive protection: %w", name, err)
			}
			return object{}, fmt.Errorf("open protected path %s: %w", name, err)
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
		identity := fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
		return object{file: file, directory: info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, identity: identity}, nil
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
	// A hostile pre-created folder may deny every metadata/read right. DELETE
	// alone can still be granted by ProgramData's FILE_DELETE_CHILD permission.
	// Do not add FILE_READ_ATTRIBUTES or alter its ACL to obtain that handle.
	openDelete := func(name string) (object, error) {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return object{}, err
		}
		var ntName windows.NTUnicodeString
		if err := windows.RtlDosPathNameToNtPathName(p, &ntName, nil, nil); err != nil {
			return object{}, err
		}
		defer func() {
			windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlFreeUnicodeString").Call(uintptr(unsafe.Pointer(&ntName)))
		}()
		attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: &ntName, Attributes: windows.OBJ_CASE_INSENSITIVE}
		var h windows.Handle
		var status windows.IO_STATUS_BLOCK
		// A synchronous CreateFile also asks for SYNCHRONIZE, which the
		// hostile DACL can deny. The native asynchronous open requests only
		// DELETE and never follows the final reparse point.
		if err := windows.NtCreateFile(&h, windows.DELETE, &attributes, &status, nil, 0,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
			windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT, 0, 0); err != nil {
			return object{}, fmt.Errorf("open quarantine DELETE handle: %w", err)
		}
		file := os.NewFile(uintptr(h), name)
		held = append(held, file)
		return object{file: file}, nil
	}
	quarantineName := func(name string) (string, error) {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		return name + ".untrusted-" + hex.EncodeToString(nonce[:]), nil
	}
	moveAside := func(item object, destination string) error {
		if err := renameDirectoryHandle(windows.Handle(item.file.Fd()), destination); err != nil {
			return fmt.Errorf("move machine folder aside (open descendants can prevent this; refusing to use it): %w", err)
		}
		log("machine folder quarantined at " + destination + "; original contents and permissions were retained there")
		return nil
	}
	read := func(item object) ([]byte, error) {
		if item.directory {
			return nil, fmt.Errorf("expected a regular file")
		}
		data, err := io.ReadAll(io.LimitReader(item.file, 4*1024*1024+1))
		if len(data) > 4*1024*1024 {
			return nil, fmt.Errorf("saved file exceeds 4 MiB")
		}
		return data, err
	}
	inspect := func(root object) ([]object, bool, error) {
		var tree []object
		trusted := true
		var walk func(object) error
		walk = func(item object) error {
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
				if err := walk(child); err != nil {
					return err
				}
			}
			return nil
		}
		err := walk(root)
		return tree, trusted, err
	}
	marker := func(root object, tree []object, trusted bool) (directoryMarker, bool) {
		if !trusted {
			return directoryMarker{}, false
		}
		for _, item := range tree {
			if item.file.Name() != filepath.Join(root.file.Name(), directoryMarkerName) {
				continue
			}
			sd, err := windows.GetSecurityInfo(windows.Handle(item.file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				return directoryMarker{}, false
			}
			if !trustedMarkerSecurity(sd) {
				return directoryMarker{}, false
			}
			data, err := read(item)
			var m directoryMarker
			if err == nil && json.Unmarshal(data, &m) == nil && m.Identity == root.identity && m.Target == path {
				return m, true
			}
		}
		return directoryMarker{}, false
	}
	closeChildren := func(tree []object) {
		for i := len(tree) - 1; i > 0; i-- {
			tree[i].file.Close()
		}
	}
	writeFresh := func(dir, name string, data []byte) error {
		p, err := windows.UTF16PtrFromString(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: final}
		h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(h), filepath.Join(dir, name))
		defer file.Close()
		if _, err := file.Write(data); err != nil {
			return err
		}
		return file.Sync()
	}
	stagePath := path + ".migrating"
	// A complete stage is durable before the old root is renamed. Recover both
	// crash windows (before/after quarantine) without losing the saved Undo.
	if staged, stageErr := open(stagePath, access, windows.FILE_SHARE_READ); stageErr == nil {
		tree, trusted, err := inspect(staged)
		if err != nil {
			return err
		}
		m, ready := marker(staged, tree, trusted)
		closeChildren(tree)
		if ready && strings.HasPrefix(m.Quarantine, path+".untrusted-") && filepath.Dir(m.Quarantine) == filepath.Dir(path) {
			old, err := open(path, access, windows.FILE_SHARE_READ)
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) && m.Previous == "" {
				old, err = openDelete(path)
			}
			if err == nil {
				if old.identity != m.Previous {
					return fmt.Errorf("pending migration belongs to a different machine folder; retaining both folders")
				}
				if err := moveAside(old, m.Quarantine); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := renameDirectoryHandle(windows.Handle(staged.file.Fd()), path); err != nil {
				return fmt.Errorf("publish pending machine-folder migration: %w", err)
			}
			log("completed pending machine-folder migration; old tree is at " + m.Quarantine)
			for _, note := range m.Notes {
				log(note)
			}
			return nil
		}
		name, err := quarantineName(stagePath)
		if err != nil {
			return err
		}
		if err := moveAside(staged, name); err != nil {
			return err
		}
	} else if errors.Is(stageErr, windows.ERROR_ACCESS_DENIED) {
		staged, err := openDelete(stagePath)
		if err != nil {
			return err
		}
		name, err := quarantineName(stagePath)
		if err != nil {
			return err
		}
		if err := moveAside(staged, name); err != nil {
			return err
		}
	} else if !errors.Is(stageErr, os.ErrNotExist) {
		return stageErr
	}
	{
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: final}
		createErr := windows.CreateDirectory(p, &attrs)
		if createErr != nil && createErr != windows.ERROR_ALREADY_EXISTS {
			return fmt.Errorf("create protected machine folder: %w", createErr)
		}
		root, err := open(path, access, windows.FILE_SHARE_READ)
		denied := errors.Is(err, windows.ERROR_ACCESS_DENIED)
		if denied {
			root, err = openDelete(path)
		}
		if err != nil {
			return err
		}
		if !denied && !root.directory {
			return fmt.Errorf("machine folder %s is not a directory", path)
		}
		var tree []object
		trusted := false
		if !denied {
			tree, trusted, err = inspect(root)
			if err != nil {
				return err
			}
		}
		_, migrated := marker(root, tree, trusted)
		if createErr == nil || migrated {
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
			if !migrated {
				b, _ := json.Marshal(directoryMarker{Identity: root.identity, Target: path})
				return writeFresh(path, directoryMarkerName, b)
			}
			return nil
		}
		oldName, err := quarantineName(path)
		if err != nil {
			return err
		}
		saved := map[string][]byte{}
		for _, item := range tree {
			name := filepath.Base(item.file.Name())
			if filepath.Dir(item.file.Name()) != path || (name != "windows-undo.json" && name != "windows-undo.json.bak" && name != "engine.pid") {
				continue
			}
			b, err := read(item)
			if err == nil && validMigratedFile(name, b) {
				saved[name] = b
			}
		}
		notes := []string{"generated engine files, old logs and the previous engine's control journal remain quarantined at " + oldName}
		if saved["windows-undo.json"] == nil && saved["windows-undo.json.bak"] != nil {
			saved["windows-undo.json"] = saved["windows-undo.json.bak"]
			notes = append(notes, "restored the validated Windows Undo backup into the fresh machine folder")
		} else if saved["windows-undo.json"] != nil {
			notes = append(notes, "restored the validated Windows Undo record into the fresh machine folder")
		} else {
			notes = append(notes, "WARNING: no valid readable Windows Undo record could be restored; Undo cannot recover those settings; original data remains at "+oldName)
		}
		if saved["engine.pid"] != nil {
			notes = append(notes, "preserved the engine PID for executable-identity-checked orphan cleanup")
		}
		closeChildren(tree)
		stage, err := windows.UTF16PtrFromString(stagePath)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(stage, &attrs); err != nil {
			return fmt.Errorf("create fresh migration folder: %w", err)
		}
		staged, err := open(stagePath, access, windows.FILE_SHARE_READ)
		if err != nil {
			return err
		}
		for _, name := range []string{"windows-undo.json", "windows-undo.json.bak", "engine.pid"} {
			if data := saved[name]; data != nil {
				if err := writeFresh(stagePath, name, data); err != nil {
					return fmt.Errorf("copy validated %s: %w", name, err)
				}
			}
		}
		m := directoryMarker{Identity: staged.identity, Target: path, Previous: root.identity, Quarantine: oldName, Notes: notes}
		b, _ := json.Marshal(m)
		if err := writeFresh(stagePath, directoryMarkerName, b); err != nil {
			return err
		}
		if checkpoint != nil {
			if err := checkpoint("staged"); err != nil {
				return err
			}
		}
		if err := moveAside(root, oldName); err != nil {
			return err
		}
		if checkpoint != nil {
			if err := checkpoint("quarantined"); err != nil {
				return err
			}
		}
		if err := renameDirectoryHandle(windows.Handle(staged.file.Fd()), path); err != nil {
			return fmt.Errorf("publish fresh machine folder (migration will resume on next start): %w", err)
		}
		for _, note := range notes {
			log(note)
		}
		return nil
	}
}

func trustedMarkerSecurity(sd *windows.SECURITY_DESCRIPTOR) bool {
	owner, _, err := sd.Owner()
	acl, _, aclErr := sd.DACL()
	if err != nil || aclErr != nil || owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || acl == nil || acl.AceCount != 2 {
		return false
	}
	seen := map[string]bool{}
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != 0x1f01ff {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return false
		}
		seen[sid.String()] = true
	}
	return len(seen) == 2
}

func validMigratedFile(name string, b []byte) bool {
	if name == "engine.pid" {
		pid, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
		return err == nil && pid > 0
	}
	if !json.Valid(b) {
		return false
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return false
	}
	v, err := js.Decode(b)
	values := js.Object(v)
	aliases := windowsundo.Aliases(raw["metrics"])
	if err != nil || windowsundo.Validate(values, aliases) != nil {
		return false
	}
	// Copy only values the native readers can actually produce. Policy reads
	// interpret DWORDs as signed int32; negative values are legitimate.
	if policy := js.Object(values["policy"])["value"]; policy != nil {
		n := js.Number(policy)
		if n < math.MinInt32 || n > math.MaxInt32 {
			return false
		}
	}
	for _, rows := range js.Object(values["metrics"]) {
		for _, row := range rows.([]any) {
			n := js.Number(js.Object(row)["metric"])
			if n < 0 || n > math.MaxUint32 || n != math.Trunc(n) {
				return false
			}
		}
	}
	return true
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
