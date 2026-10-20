package winplatform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMachineCleanupNames(t *testing.T) {
	for _, name := range []string{"Net Switch", "Net Switch.migrating", "Net Switch.untrusted-" + strings.Repeat("a", 24), "Net Switch.migrating.untrusted-" + strings.Repeat("b", 24)} {
		if !machineCleanupName(name, "Net Switch") {
			t.Fatal("missed generated name", name)
		}
	}
	for _, name := range []string{"Net Switch.migrating-other-app", "Net Switch.untrusted-not-ours", "Net Switch2", "Net Switch.untrusted-" + strings.Repeat("z", 24)} {
		if machineCleanupName(name, "Net Switch") {
			t.Fatal("accepted unrelated name", name)
		}
	}
}

func TestUninstallRecoversPendingUndoAndRetainsUncertainty(t *testing.T) {
	hostedSecurity(t)
	for _, body := range []string{validUndo, "damaged", "damaged-with-backup"} {
		t.Run(body, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "windows-undo.json"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if body == "damaged-with-backup" {
				if err := os.WriteFile(filepath.Join(root, "windows-undo.json.bak"), []byte(validUndo), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stop := errors.New("interrupted")
			if err := protectDirectory(root, func(s string) { t.Log(s) }, func(point string) error {
				if point == "quarantined" {
					return stop
				}
				return nil
			}); !errors.Is(err, stop) {
				t.Fatal(err)
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("fixture did not leave the live path absent", err)
			}
			err := PrepareMachineUninstall(root, func(s string) { t.Log(s) })
			if body != validUndo {
				if err == nil {
					t.Fatal("lost Undo became permission to delete")
				}
				old, _ := filepath.Glob(root + ".untrusted-*")
				if len(old) != 1 {
					t.Fatal("damaged Undo quarantine lost")
				}
				if b, err := os.ReadFile(filepath.Join(old[0], "windows-undo.json")); err != nil || string(b) != body {
					t.Fatal("uncertain Undo deleted", err)
				}
				if err := ProtectDirectory(root); err != nil {
					t.Fatal(err)
				}
				if err := PrepareMachineUninstall(root, func(s string) { t.Log(s) }); err == nil {
					t.Fatal("second uninstall forgot the earlier Undo loss")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(filepath.Join(root, "windows-undo.json")); err != nil || string(b) != body {
				t.Fatal("restore would read an empty record", err)
			}
			t.Log("uninstall preparation recovered certified Undo before restoration")
		})
	}
}

func TestUninstallAllowsLegacyFolderWithoutUndo(t *testing.T) {
	hostedSecurity(t)
	root := filepath.Join(t.TempDir(), "machine")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := PrepareMachineUninstall(root, func(s string) { t.Log(s) }); err != nil {
			t.Fatal("a never-configured installation was mistaken for damaged Undo", err)
		}
	}
}

func TestMachineCleanupUnlinksOnlyAdminOwnedEntries(t *testing.T) {
	hostedSecurity(t)
	base := t.TempDir()
	root := filepath.Join(base, "machine")
	other := filepath.Join(base, "other-configured-machine")
	for _, path := range []string{root, other} {
		if err := ProtectDirectory(path); err != nil {
			t.Fatal(err)
		}
	}
	outside := lockoutOutside(t)
	// Establish admin ownership on the actual target before linking. Cleanup
	// must only remove the extra link, without changing its shared metadata.
	sd, _ := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	owner, _, _ := sd.Owner()
	acl, _, _ := sd.DACL()
	for _, path := range []string{outside, filepath.Join(outside, "record")} {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	dirACL, fileACL := fileSecurity(t, outside), fileSecurity(t, filepath.Join(outside, "record"))
	old := root + ".untrusted-" + strings.Repeat("1", 24)
	stage := root + ".migrating"
	for _, path := range []string{old, stage} {
		if err := ProtectDirectory(path); err != nil {
			t.Fatal(err)
		}
		plantMachineOccupant(t, filepath.Join(path, "junction"), "junction", outside)
		plantMachineOccupant(t, filepath.Join(path, "hardlink"), "hardlink", outside)
	}
	untrusted := root + ".migrating.untrusted-" + strings.Repeat("2", 24)
	if err := os.Mkdir(untrusted, 0700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(untrusted, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, old, stage, untrusted} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("cleanup fixture never existed", err)
		}
	}
	var logs []string
	if err := CleanupMachineData(root, func(s string) { logs = append(logs, s) }); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, old, stage} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("admin-owned artifact survived", path, err)
		}
	}
	if _, err := os.Stat(untrusted); err != nil || !strings.Contains(strings.Join(logs, "\n"), "retained non-admin-owned") {
		t.Fatal("non-admin-owned occupant was not retained and diagnosed", err, logs)
	}
	if cert, err := directoryCertificate(root); err != nil || cert != "" {
		t.Fatal("uninstalled machine certificate survived", cert, err)
	}
	if cert, err := directoryCertificate(other); err != nil || cert == "" {
		t.Fatal("another configured machine lost its certificate", err)
	}
	assertOutsideUnchanged(t, outside, dirACL, fileACL)
	t.Log("admin-owned root, stage and quarantine removed; user-owned occupant and outside links retained safely")
}

func TestMachineCleanupContinuesAfterDeniedOccupant(t *testing.T) {
	hostedSecurity(t)
	base := t.TempDir()
	root := filepath.Join(base, "machine")
	denied := root + ".untrusted-" + strings.Repeat("0", 24)
	if err := os.Mkdir(denied, 0700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, _ := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(D;;FA;;;BA)(A;;FA;;;SY)")
	owner, _, _ := sd.Owner()
	acl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(denied, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sd, _ := windows.SecurityDescriptorFromString("D:P(A;;FA;;;BA)")
		acl, _, _ := sd.DACL()
		_ = windows.SetNamedSecurityInfo(denied, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	})
	if err := ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	var logs []string
	err = CleanupMachineData(root, func(s string) { logs = append(logs, s) })
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || !strings.Contains(strings.Join(logs, "\n"), denied) {
		t.Fatal("denied decoy was not exercised and diagnosed", err, logs)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("decoy prevented independent admin-owned cleanup", err)
	}
	if cert, err := directoryCertificate(root); err != nil || cert != "" {
		t.Fatal("decoy prevented certificate cleanup", cert, err)
	}
	if _, err := windows.GetNamedSecurityInfo(denied, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err != nil {
		t.Fatal("the user-owned decoy disappeared", err)
	}
	t.Log("inaccessible decoy retained and logged; independent admin-owned data and certificate removed")
}
