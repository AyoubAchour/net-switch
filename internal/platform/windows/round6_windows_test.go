package winplatform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMachineFolderDoesNotImportHostileRecords(t *testing.T) {
	hostedSecurity(t)
	for _, kind := range []string{"user-owned-root", "writable-root", "user-owned-record", "linked-child"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			trustedLegacyDirectory(t, root)
			records := map[string]string{"windows-undo.json": validUndo, "windows-undo.json.bak": validUndo, "engine.pid": "1234"}
			for name, body := range records {
				if !validMigratedFile(name, []byte(body)) {
					t.Fatal("planted record is not well-formed", name)
				}
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "user-owned-root", "user-owned-record":
				user, err := windows.GetCurrentProcessToken().GetTokenUser()
				if err != nil {
					t.Fatal(err)
				}
				target := root
				if kind == "user-owned-record" {
					target = filepath.Join(root, "windows-undo.json")
				}
				if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
					t.Fatal(err)
				}
			case "writable-root":
				sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
				if err != nil {
					t.Fatal(err)
				}
				acl, _, _ := sd.DACL()
				if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
					t.Fatal(err)
				}
			case "linked-child":
				outside := lockoutOutside(t)
				if err := os.Link(filepath.Join(outside, "record"), filepath.Join(root, "linked")); err != nil {
					t.Fatal(err)
				}
			}
			before, err := eagerFileInfo(root)
			if err != nil {
				t.Fatal(err)
			}
			security := fileSecurity(t, root)
			var logs []string
			if err := protectDirectory(root, func(s string) { logs = append(logs, s) }, nil); err != nil {
				t.Fatal(err)
			}
			old, err := filepath.Glob(root + ".untrusted-*")
			if err != nil || len(old) != 1 {
				t.Fatal("hostile tree not quarantined", old, err)
			}
			quarantined, err := eagerFileInfo(old[0])
			if err != nil || !os.SameFile(before, quarantined) || fileSecurity(t, old[0]) != security {
				t.Fatal("original object or permissions were changed", err)
			}
			for name, body := range records {
				if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("hostile record imported", name, err)
				}
				if data, err := os.ReadFile(filepath.Join(old[0], name)); err != nil || string(data) != body {
					t.Fatal("quarantined record changed", name, err)
				}
			}
			if !strings.Contains(strings.Join(logs, "\n"), "Windows Undo record was not imported") ||
				!strings.Contains(strings.Join(logs, "\n"), old[0]) {
				t.Fatal("rejected Undo import was not diagnosed", logs)
			}
			for i := 0; i < 2; i++ {
				if err := ProtectDirectory(root); err != nil {
					t.Fatal("clean startup failed", err)
				}
				if err := PrepareMachineUninstall(root, func(s string) { t.Log(s) }); err == nil {
					t.Fatal("uninstall forgot that untrusted Undo was retained")
				}
			}
			t.Log("well-formed primary, backup and PID stayed quarantined; warning persisted across startup and uninstall retries")
		})
	}
}

func TestMachineFolderBlockedStageRequiresCertifiedLiveRoot(t *testing.T) {
	hostedSecurity(t)
	for _, state := range []string{"certified", "legacy", "missing", "pending-staged", "pending-quarantined"} {
		t.Run(state, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			stage := root + ".migrating"
			switch state {
			case "certified":
				if err := ProtectDirectory(root); err != nil {
					t.Fatal(err)
				}
			case "legacy", "pending-staged", "pending-quarantined":
				trustedLegacyDirectory(t, root)
			}
			if state != "missing" {
				if err := os.WriteFile(filepath.Join(root, "windows-undo.json"), []byte(validUndo), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(state, "pending-") {
				stop := errors.New("interrupted")
				if err := protectDirectory(root, func(s string) { t.Log(s) }, func(point string) error {
					if point == strings.TrimPrefix(state, "pending-") {
						return stop
					}
					return nil
				}); !errors.Is(err, stop) {
					t.Fatal("pending migration not established", err)
				}
			} else if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			stageBefore, err := eagerFileInfo(stage)
			if err != nil {
				t.Fatal(err)
			}
			rootBefore, rootErr := eagerFileInfo(root)
			certificate, err := directoryCertificate(root)
			if err != nil {
				t.Fatal(err)
			}
			p, _ := windows.UTF16PtrFromString(stage)
			held, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(held)
			// Prove the live fixture prevents DELETE before crediting startup.
			probe, err := windows.CreateFile(p, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err != windows.ERROR_SHARING_VIOLATION {
				if err == nil {
					windows.CloseHandle(probe)
				}
				t.Fatal("held stage did not block DELETE", err)
			}
			for i := 0; i < 2; i++ {
				var logs []string
				ready := false
				err := prepareDirectory(root, func(s string) { logs = append(logs, s) }, nil, func(directoryMarker) error {
					ready = true
					return nil
				})
				if state == "certified" {
					if err != nil || !ready || !strings.Contains(strings.Join(logs, "\n"), "skipped blocked staging occupant") {
						t.Fatal("held stage blocked certified startup or was not logged", err, ready, logs)
					}
					if data, err := os.ReadFile(filepath.Join(root, "windows-undo.json")); err != nil || string(data) != validUndo {
						t.Fatal("certified live Undo changed", err)
					}
				} else if err == nil || ready {
					t.Fatal("uncertified live root bypassed pending stage", err, ready)
				}
				stageAfter, err := eagerFileInfo(stage)
				if err != nil || !os.SameFile(stageBefore, stageAfter) {
					t.Fatal("held stage was replaced", err)
				}
				rootAfter, err := eagerFileInfo(root)
				if os.IsNotExist(rootErr) {
					if !os.IsNotExist(err) {
						t.Fatal("missing live root was created during blocked recovery", err)
					}
				} else if rootErr != nil || err != nil || !os.SameFile(rootBefore, rootAfter) {
					t.Fatal("live identity changed during blocked stage handling", rootErr, err)
				}
				if after, err := directoryCertificate(root); err != nil || after != certificate {
					t.Fatal("certificate changed during blocked stage handling", err)
				}
			}
			t.Log("DELETE-sharing blocker remained held through two starts; only certified live root reached readiness")
		})
	}
}
