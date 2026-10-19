package winplatform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const validUndo = `{"metrics":{"Wi-Fi":[{"family":"IPv6","automatic":false,"metric":25}]},"policy":{"value":-2147483648}}`

// On Windows os.Stat can defer the file-ID query until os.SameFile. If the
// pathname has been replaced by then, both snapshots describe the new object.
// File.Stat captures the ID now; close the handle before testing any rename.
func eagerFileInfo(path string) (os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func TestMachineFolderMigrationPreservesValidatedRecordsOnce(t *testing.T) {
	hostedSecurity(t)
	for _, primary := range []string{validUndo, "damaged", "missing"} {
		t.Run(primary, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			// Simulate an admin-only legacy tree without a fresh-object marker.
			if err := os.Remove(filepath.Join(root, directoryMarkerName)); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"windows-undo.json.bak": validUndo, "engine.pid": "1234", "engine-config.json": "untrusted configuration", "control-journal.json": "old instance"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if primary != "missing" {
				if err := os.WriteFile(filepath.Join(root, "windows-undo.json"), []byte(primary), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := eagerFileInfo(root)
			if err != nil {
				t.Fatal(err)
			}
			var logs []string
			if err := protectDirectory(root, func(s string) { logs = append(logs, s) }, nil); err != nil {
				t.Fatal(err)
			}
			after, err := eagerFileInfo(root)
			if err != nil || os.SameFile(before, after) {
				t.Fatal("legacy folder identity was retained", err)
			}
			if b, err := os.ReadFile(filepath.Join(root, "windows-undo.json")); err != nil || string(b) != validUndo {
				t.Fatal("Undo was lost", string(b), err)
			}
			if b, err := os.ReadFile(filepath.Join(root, "engine.pid")); err != nil || string(b) != "1234" {
				t.Fatal("PID handoff was lost", string(b), err)
			}
			if _, err := os.Stat(filepath.Join(root, "engine-config.json")); !os.IsNotExist(err) {
				t.Fatal("imported an executable configuration", err)
			}
			old, err := filepath.Glob(root + ".untrusted-*")
			if err != nil || len(old) != 1 || !strings.Contains(strings.Join(logs, "\n"), old[0]) || !strings.Contains(strings.Join(logs, "\n"), "Windows Undo") {
				t.Fatal("quarantine/recovery not diagnosed", old, logs, err)
			}
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			again, err := eagerFileInfo(root)
			if err != nil || !os.SameFile(after, again) {
				t.Fatal("migrated twice", err)
			}
		})
	}
}

func TestMachineFolderMigrationResumesAfterInterruption(t *testing.T) {
	hostedSecurity(t)
	for _, stopAt := range []string{"staged", "quarantined"} {
		t.Run(stopAt, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "windows-undo.json"), []byte(validUndo), 0600); err != nil {
				t.Fatal(err)
			}
			original, err := eagerFileInfo(root)
			if err != nil {
				t.Fatal(err)
			}
			interrupted := errors.New("interrupted migration")
			err = protectDirectory(root, func(s string) { t.Log(s) }, func(stage string) error {
				if stage == stopAt {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("fault did not execute", err)
			}
			staged, err := eagerFileInfo(root + ".migrating")
			if err != nil {
				t.Fatal("pending stage never existed", err)
			}
			live, err := eagerFileInfo(root)
			if stopAt == "quarantined" {
				if !os.IsNotExist(err) {
					t.Fatal("fault did not leave the live root absent", err)
				}
			} else if err != nil || !os.SameFile(original, live) {
				t.Fatal("staging replaced the old root before commit", err)
			}
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			live, err = eagerFileInfo(root)
			if err != nil || !os.SameFile(staged, live) {
				t.Fatal("recovery did not publish the staged directory", err)
			}
			if _, err := os.Stat(root + ".migrating"); !os.IsNotExist(err) {
				t.Fatal("pending stage was not consumed", err)
			}
			old, err := filepath.Glob(root + ".untrusted-*")
			if err != nil || len(old) != 1 {
				t.Fatal("original tree was not quarantined once", old, err)
			}
			quarantined, err := eagerFileInfo(old[0])
			if err != nil || !os.SameFile(original, quarantined) {
				t.Fatal("quarantine lost the original directory", err)
			}
			if b, err := os.ReadFile(filepath.Join(root, "windows-undo.json")); err != nil || string(b) != validUndo {
				t.Fatal("interruption lost Undo", string(b), err)
			}
		})
	}
}

func TestMachineFolderDeniedMetadataUsesDeleteChild(t *testing.T) {
	hostedSecurity(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "machine")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	// Match ProgramData's admin delete-child right. The hostile child denies
	// all access to Administrators; a combined metadata open must really fail.
	parentSD, _ := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	owner, _, _ := parentSD.Owner()
	acl, _, _ := parentSD.DACL()
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	denied, _ := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(D;;FA;;;BA)(A;;FA;;;SY)")
	denyOwner, _, _ := denied.Owner()
	denyACL, _, _ := denied.DACL()
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, denyOwner, nil, denyACL, nil); err != nil {
		t.Fatal(err)
	}
	// Cleanup has permission to restore the disposable fixture, after the proof.
	t.Cleanup(func() {
		old, _ := filepath.Glob(root + ".untrusted-*")
		for _, path := range append(old, root) {
			_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
		}
	})
	p, _ := windows.UTF16PtrFromString(root)
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.DELETE|windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != windows.ERROR_ACCESS_DENIED {
		if err == nil {
			windows.CloseHandle(h)
		}
		t.Fatal("fixture did not deny metadata access", err)
	}
	var logs []string
	if err := protectDirectory(root, func(s string) { logs = append(logs, s) }, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "Undo cannot recover") {
		t.Fatal("unreadable Undo loss was silent", logs)
	}
}

func TestMigratedFilesValidateNativeValues(t *testing.T) {
	for _, body := range []string{validUndo, `{"metrics":{},"policy":{"value":null}}`} {
		if !validMigratedFile("windows-undo.json", []byte(body)) {
			t.Fatal("legitimate native record refused", body)
		}
	}
	for _, body := range []string{`{"metrics":{"Wi-Fi":[{"family":"IPv4","automatic":true,"metric":-1}]},"policy":{}}`, `{"metrics":{},"policy":{"value":2147483648}}`, `{"metrics":{"Wi-Fi":"bad"},"policy":{}}`, "null", validUndo + "{}"} {
		if validMigratedFile("windows-undo.json", []byte(body)) {
			t.Fatal("invalid native record accepted", body)
		}
	}
}

func TestMachineFolderRejectsTransplantedMigrationMarker(t *testing.T) {
	hostedSecurity(t)
	base := t.TempDir()
	first, second := filepath.Join(base, "first"), filepath.Join(base, "second")
	for _, path := range []string{first, second} {
		if err := ProtectDirectory(path); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(first, directoryMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, directoryMarkerName), b, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := eagerFileInfo(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := ProtectDirectory(second); err != nil {
		t.Fatal(err)
	}
	after, err := eagerFileInfo(second)
	if err != nil || os.SameFile(before, after) {
		t.Fatal("transplanted admin-owned marker was trusted", err)
	}
}
