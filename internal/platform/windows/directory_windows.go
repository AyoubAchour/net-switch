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
	Nonce                                  string
	Notes                                  []string
}

func newDirectoryMarker(identity, target, previous, quarantine string, notes []string) (directoryMarker, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return directoryMarker{}, err
	}
	return directoryMarker{Identity: identity, Target: target, Previous: previous, Quarantine: quarantine, Nonce: hex.EncodeToString(nonce[:]), Notes: notes}, nil
}

func (m directoryMarker) certificate() string { return m.Identity + "|" + m.Nonce }

// ProtectDirectory migrates legacy trees even when their current ACL looks
// safe: tightening a DACL cannot revoke an old WRITE_DAC handle. Only a marker
// owned by Administrators, bound to this fresh directory's identity AND its
// independent HKLM certificate, permits reuse. Node can launder a planted
// file's ownership, but cannot certify it. The caller holds the instance lock.
func ProtectDirectory(path string) error {
	return protectDirectory(path, func(s string) { fmt.Fprintln(os.Stderr, s) }, nil)
}

func protectDirectory(path string, log func(string), checkpoint func(string) error) error {
	return prepareDirectory(path, log, checkpoint, nil)
}

func prepareDirectory(path string, log func(string), checkpoint func(string) error, onReady func(directoryMarker) error) error {
	ready := func(m directoryMarker) error {
		if onReady != nil {
			return onReady(m)
		}
		return nil
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	certificate, err := directoryCertificate(path)
	if err != nil {
		return fmt.Errorf("read machine-folder provenance: %w", err)
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
			file.Close()
			return object{}, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			file.Close()
			return object{}, fmt.Errorf("%s is a reparse point, which Net Switch will not follow", name)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks > 1 {
			file.Close()
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
	quarantine := func(name string) error {
		item, err := openDelete(name)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return err
		}
		defer item.file.Close()
		destination, err := quarantineName(name)
		if err != nil {
			return err
		}
		return moveAside(item, destination)
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
			data, err := read(item)
			if err == nil {
				return parseDirectoryMarker(sd, data, root.identity, path, certificate)
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
	publish := func(staged object, m directoryMarker) error {
		// The HKLM certificate authenticates this stage, not an occupant of
		// its destination. A crash or a user creating a folder in the rename
		// gap must not permanently prevent recovery. Never replace in place.
		for attempt := 0; attempt < 32; attempt++ {
			err := renameDirectoryHandle(windows.Handle(staged.file.Fd()), path)
			if err == nil {
				return nil
			}
			old, openErr := open(path, access, windows.FILE_SHARE_READ)
			if errors.Is(openErr, os.ErrNotExist) {
				return err
			}
			if openErr == nil && old.identity == m.Previous {
				err = moveAside(old, m.Quarantine)
				old.file.Close()
			} else {
				if openErr == nil {
					old.file.Close()
				}
				err = quarantine(path)
			}
			if err != nil {
				return err
			}
		}
		return fmt.Errorf("machine-folder destination kept changing; certified migration retained for next start")
	}
	// A complete stage is durable before the old root is renamed. Recover both
	// crash windows (before/after quarantine) without losing the saved Undo.
	if staged, stageErr := open(stagePath, access, windows.FILE_SHARE_READ); stageErr == nil {
		var tree []object
		var m directoryMarker
		certified := false
		// Never enumerate a staging tree on the strength of its name. Its
		// owner and ACL must be trusted before opening any descendant.
		sd, err := windows.GetSecurityInfo(windows.Handle(staged.file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err == nil && staged.directory && trustedMachineSecurity(sd) {
			var trusted bool
			tree, trusted, err = inspect(staged)
			if err == nil {
				m, certified = marker(staged, tree, trusted)
			}
		}
		closeChildren(tree)
		if certified && strings.HasPrefix(m.Quarantine, path+".untrusted-") && filepath.Dir(m.Quarantine) == filepath.Dir(path) {
			// A previous certificate write may have become visible before its
			// flush failed. Reaffirm durability before moving the original.
			if err := certifyDirectory(path, m.certificate()); err != nil {
				return err
			}
			if err := publish(staged, m); err != nil {
				return fmt.Errorf("publish pending machine-folder migration: %w", err)
			}
			log("completed pending machine-folder migration; old tree is at " + m.Quarantine)
			for _, note := range m.Notes {
				log(note)
			}
			return ready(m)
		}
		staged.file.Close()
		if err := quarantine(stagePath); err != nil {
			return err
		}
	} else if !errors.Is(stageErr, os.ErrNotExist) {
		if err := quarantine(stagePath); err != nil {
			return err
		}
	}
	{
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: final}
		createErr := windows.CreateDirectory(p, &attrs)
		if createErr != nil && createErr != windows.ERROR_ALREADY_EXISTS && createErr != windows.ERROR_FILE_EXISTS && createErr != windows.ERROR_ACCESS_DENIED {
			return fmt.Errorf("create protected machine folder: %w", createErr)
		}
		root, err := open(path, access, windows.FILE_SHARE_READ)
		unreadable := err != nil
		if unreadable {
			root, err = openDelete(path)
		}
		if err != nil {
			return err
		}
		var tree []object
		trusted := false
		if !unreadable && root.directory {
			tree, trusted, err = inspect(root)
			if err != nil {
				// A linked or inaccessible descendant cannot authenticate a
				// tree. Keep any readable, validated recovery records, then
				// quarantine the whole original without altering its ACLs.
				trusted = false
			}
		}
		m, migrated := marker(root, tree, trusted)
		if (createErr == nil && trusted) || migrated {
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
				m, err := newDirectoryMarker(root.identity, path, "", "", nil)
				if err != nil {
					return err
				}
				b, _ := json.Marshal(m)
				if err := writeFresh(path, directoryMarkerName, b); err != nil {
					return err
				}
				if err := certifyDirectory(path, m.certificate()); err != nil {
					return err
				}
				return ready(m)
			}
			return ready(m)
		}
		oldName, err := quarantineName(path)
		if err != nil {
			return err
		}
		saved := map[string][]byte{}
		closeChildren(tree)
		if !unreadable && root.directory {
			// Inspect can stop at an unrelated hostile child. Read each
			// allowlisted record independently through the pinned root.
			for _, name := range []string{"windows-undo.json", "windows-undo.json.bak", "engine.pid"} {
				item, err := open(filepath.Join(path, name), windows.FILE_READ_DATA, windows.FILE_SHARE_READ)
				if err != nil {
					continue
				}
				b, err := read(item)
				item.file.Close()
				if err == nil && validMigratedFile(name, b) {
					saved[name] = b
				}
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
		m, err = newDirectoryMarker(staged.identity, path, root.identity, oldName, notes)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(m)
		if err := writeFresh(stagePath, directoryMarkerName, b); err != nil {
			return err
		}
		if err := certifyDirectory(path, m.certificate()); err != nil {
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
		if err := publish(staged, m); err != nil {
			return fmt.Errorf("publish fresh machine folder (migration will resume on next start): %w", err)
		}
		for _, note := range notes {
			log(note)
		}
		return ready(m)
	}
}

func parseDirectoryMarker(sd *windows.SECURITY_DESCRIPTOR, data []byte, identity, target, certificate string) (directoryMarker, bool) {
	var m directoryMarker
	if trustedMarkerSecurity(sd) && json.Unmarshal(data, &m) == nil && m.Identity == identity && m.Target == target && len(m.Nonce) == 64 {
		if _, err := hex.DecodeString(m.Nonce); err == nil && certificate == m.certificate() {
			return m, true
		}
	}
	return directoryMarker{}, false
}

func trustedMarkerSecurity(sd *windows.SECURITY_DESCRIPTOR) bool {
	return trustedAdminSecurity(sd, 0x1f01ff)
}

func trustedAdminSecurity(sd *windows.SECURITY_DESCRIPTOR, access windows.ACCESS_MASK) bool {
	owner, _, err := sd.Owner()
	acl, _, aclErr := sd.DACL()
	if err != nil || aclErr != nil || owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || acl == nil || acl.AceCount != 2 {
		return false
	}
	seen := map[string]bool{}
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != access {
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

type directoryRenameInfo struct {
	Replace uint32
	Root    windows.Handle
	Length  uint32
	Name    [1]uint16
}

func directoryRenameBuffer(destination string) ([]byte, error) {
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return nil, err
	}
	var layout directoryRenameInfo
	offset := int(unsafe.Offsetof(layout.Name))
	// FileNameLength excludes the NUL, but the Win32 DOS-path conversion
	// consumes a terminated FileName before issuing the counted NT rename.
	// Keep that terminator inside our allocation, including at size classes
	// where there is no spare zeroed allocator padding after the pathname.
	b := make([]byte, max(int(unsafe.Sizeof(layout)), offset+len(name)*2))
	info := (*directoryRenameInfo)(unsafe.Pointer(&b[0]))
	info.Length = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.Name[0], len(name)), name)
	return b, nil
}

func renameDirectoryHandle(h windows.Handle, destination string) error {
	b, err := directoryRenameBuffer(destination)
	if err != nil {
		return err
	}
	if err := windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &b[0], uint32(len(b))); err != nil {
		return fmt.Errorf("rename machine folder to %q: %w", destination, err)
	}
	return nil
}
