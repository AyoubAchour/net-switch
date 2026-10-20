package winplatform

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func plantMachineOccupant(t *testing.T, path, kind, outside string) {
	t.Helper()
	switch kind {
	case "junction":
		if b, err := exec.Command("cmd.exe", "/c", "mklink", "/J", path, outside).CombinedOutput(); err != nil {
			t.Fatalf("create junction: %v %s", err, b)
		}
	case "hardlink":
		if err := os.Link(filepath.Join(outside, "record"), path); err != nil {
			t.Fatal(err)
		}
	default:
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if kind == "children" {
			plantMachineOccupant(t, filepath.Join(path, "junction"), "junction", outside)
			plantMachineOccupant(t, filepath.Join(path, "hardlink"), "hardlink", outside)
		}
	}
}

func lockoutOutside(t *testing.T) string {
	t.Helper()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "record"), []byte("outside data"), 0600); err != nil {
		t.Fatal(err)
	}
	return outside
}

func assertOutsideUnchanged(t *testing.T, outside, dirACL, fileACL string) {
	t.Helper()
	if fileSecurity(t, outside) != dirACL || fileSecurity(t, filepath.Join(outside, "record")) != fileACL {
		t.Fatal("quarantine changed an outside ACL")
	}
	if b, err := os.ReadFile(filepath.Join(outside, "record")); err != nil || string(b) != "outside data" {
		t.Fatal("quarantine changed outside data", err)
	}
}

func TestMachineFolderQuarantinesPlantedNames(t *testing.T) {
	hostedSecurity(t)
	for _, location := range []string{"stage", "root"} {
		for _, kind := range []string{"junction", "hardlink", "children", "trusted-children"} {
			t.Run(location+"/"+kind, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "machine")
				occupant := root
				if location == "stage" {
					occupant += ".migrating"
				}
				outside := lockoutOutside(t)
				dirACL, fileACL := fileSecurity(t, outside), fileSecurity(t, filepath.Join(outside, "record"))
				plantKind := kind
				if kind == "trusted-children" {
					plantKind = "children"
				}
				plantMachineOccupant(t, occupant, plantKind, outside)
				if kind == "children" || kind == "trusted-children" {
					user, err := windows.GetCurrentProcessToken().GetTokenUser()
					if err != nil {
						t.Fatal(err)
					}
					owner := user.User.Sid.String()
					if kind == "trusted-children" {
						owner = "BA"
					}
					sd, _ := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
					sid, _, _ := sd.Owner()
					acl, _, _ := sd.DACL()
					if err := windows.SetNamedSecurityInfo(occupant, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sid, nil, acl, nil); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := os.Lstat(occupant); err != nil {
					t.Fatal("plant did not exist", err)
				}
				var logs []string
				if err := protectDirectory(root, func(s string) { logs = append(logs, s) }, nil); err != nil {
					t.Fatal("startup blocked by planted name", err)
				}
				old, err := filepath.Glob(occupant + ".untrusted-*")
				if err != nil || len(old) != 1 || !strings.Contains(strings.Join(logs, "\n"), old[0]) {
					t.Fatal("occupant not quarantined and logged", old, logs, err)
				}
				if err := ProtectDirectory(root); err != nil {
					t.Fatal("second startup blocked", err)
				}
				assertOutsideUnchanged(t, outside, dirACL, fileACL)
				t.Log("two starts succeeded; planted occupant quarantined and logged; outside ACLs and data unchanged")
			})
		}
	}
}

func TestCertifiedMigrationQuarantinesPublishRace(t *testing.T) {
	hostedSecurity(t)
	for _, crash := range []bool{false, true} {
		for _, kind := range []string{"directory", "denied", "junction", "hardlink", "children"} {
			name := kind + "/same-start"
			if crash {
				name = kind + "/restart"
			}
			t.Run(name, func(t *testing.T) {
				base := t.TempDir()
				root := filepath.Join(base, "machine")
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "windows-undo.json"), []byte(validUndo), 0600); err != nil {
					t.Fatal(err)
				}
				outside := lockoutOutside(t)
				dirACL, fileACL := fileSecurity(t, outside), fileSecurity(t, filepath.Join(outside, "record"))
				// Match ProgramData's DELETE_CHILD right even if the planted
				// destination denies Administrators all rights.
				sd, _ := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
				owner, _, _ := sd.Owner()
				acl, _, _ := sd.DACL()
				if err := windows.SetNamedSecurityInfo(base, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if kind == "denied" {
						names, _ := filepath.Glob(root + ".untrusted-*")
						for _, name := range names {
							_ = windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
						}
					}
				})
				var logs []string
				log := func(s string) { logs = append(logs, s) }
				stopped := errors.New("crash after plant")
				planted := false
				err := protectDirectory(root, log, func(point string) error {
					if point != "quarantined" {
						return nil
					}
					if _, err := os.Lstat(root); !os.IsNotExist(err) {
						t.Fatal("publish gap not reached", err)
					}
					plantMachineOccupant(t, root, kind, outside)
					if kind == "denied" {
						deny, _ := windows.SecurityDescriptorFromString("D:P(D;;FA;;;BA)(A;;FA;;;SY)")
						dacl, _, _ := deny.DACL()
						if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
							t.Fatal(err)
						}
					}
					planted = true
					if crash {
						return stopped
					}
					return nil
				})
				if !planted {
					t.Fatal("fault injection did not run", err)
				}
				if crash {
					if !errors.Is(err, stopped) {
						t.Fatal("crash did not stop before publication", err)
					}
					err = protectDirectory(root, log, nil)
				}
				if err != nil {
					t.Fatal("planted occupant locked out startup", err)
				}
				old, err := filepath.Glob(root + ".untrusted-*")
				if err != nil || len(old) != 2 {
					t.Fatal("old directory and planted occupant not both quarantined", old, err)
				}
				for _, name := range old {
					if !strings.Contains(strings.Join(logs, "\n"), name) {
						t.Fatal("quarantine missing from logs", name, logs)
					}
				}
				if b, err := os.ReadFile(filepath.Join(root, "windows-undo.json")); err != nil || string(b) != validUndo {
					t.Fatal("certified Undo lost", err)
				}
				if err := ProtectDirectory(root); err != nil {
					t.Fatal("next startup failed", err)
				}
				assertOutsideUnchanged(t, outside, dirACL, fileACL)
				t.Log("publish gap exercised; both occupants quarantined and logged; certified Undo and outside ACLs preserved")
			})
		}
	}
}
