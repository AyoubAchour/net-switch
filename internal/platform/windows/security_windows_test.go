package winplatform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestTrustedMachineSecurity(t *testing.T) {
	for _, test := range []struct {
		name, sddl string
		trusted    bool
	}{
		{"administrators", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true},
		{"system", "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"readers", "O:BAD:P(A;;FA;;;BA)(A;;FRFX;;;BU)", true},
		{"user owner", "O:BUD:P(A;;FA;;;BA)", false},
		{"null DACL", "O:BAD:NO_ACCESS_CONTROL", false},
		{"missing DACL", "O:BA", false},
		{"inherit-only writer", "O:BAD:P(A;;FA;;;BA)(A;OICIIO;FW;;;BU)", false},
		{"denied writer", "O:BAD:P(D;;FW;;;BU)(A;;FA;;;BA)(A;;FW;;;BU)", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if got := trustedMachineSecurity(sd); got != test.trusted {
				t.Fatalf("trusted=%t for %s", got, test.sddl)
			}
		})
	}
	for _, right := range []uint32{windows.WRITE_DAC, windows.WRITE_OWNER, windows.DELETE,
		windows.FILE_WRITE_DATA, windows.FILE_APPEND_DATA, windows.FILE_WRITE_EA,
		windows.FILE_WRITE_ATTRIBUTES, fileDeleteChild, windows.GENERIC_WRITE, windows.GENERIC_ALL} {
		t.Run(fmt.Sprintf("untrusted grant %x", right), func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:BAD:P(A;;FA;;;BA)(A;;0x%x;;;BU)", right))
			if err != nil {
				t.Fatal(err)
			}
			if trustedMachineSecurity(sd) {
				t.Fatal("dangerous non-admin grant was trusted")
			}
		})
	}
}

func TestMachineFolderKeepsTrustedDataAndObjectIdentity(t *testing.T) {
	hostedSecurity(t)
	root := filepath.Join(t.TempDir(), "machine")
	if err := ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "child", "nested")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "record")
	if err := os.WriteFile(path, []byte("trusted saved data"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := ProtectDirectory(root); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("trusted object was replaced: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "trusted saved data" {
		t.Fatal(string(b), err)
	}
	if old, err := filepath.Glob(root + ".untrusted-*"); err != nil || len(old) != 0 {
		t.Fatalf("trusted data was quarantined: %v %v", old, err)
	}
	for _, p := range []string{root, filepath.Dir(dir), dir, path} {
		t.Logf("trusted %s: %s", filepath.Base(p), fileSecurity(t, p))
	}
}

func TestMachineFolderQuarantinesUntrustedDescendantOwner(t *testing.T) {
	hostedSecurity(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "child", "nested")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(dir, "record")
			if err := os.WriteFile(record, []byte("keep quarantined data"), 0600); err != nil {
				t.Fatal(err)
			}
			target := dir
			if kind == "file" {
				target = record
			}
			if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			before := fileSecurity(t, target)
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			old, err := filepath.Glob(root + ".untrusted-*")
			if err != nil || len(old) != 1 {
				t.Fatal(old, err)
			}
			relative, _ := filepath.Rel(root, target)
			if after := fileSecurity(t, filepath.Join(old[0], relative)); before != after {
				t.Fatalf("quarantine rewrote the original ACL: %s -> %s", before, after)
			}
			if b, err := os.ReadFile(filepath.Join(old[0], "child", "nested", "record")); err != nil || string(b) != "keep quarantined data" {
				t.Fatal(string(b), err)
			}
		})
	}
}

func TestVersionResultsStayInsideResourceBuffer(t *testing.T) {
	b := []byte{'A', 0, 'B', 0, 0, 0, 0, 0}
	for _, test := range []struct {
		offset int
		units  uint32
		want   string
	}{
		{0, 3, "AB"}, {2, 2, "B"}, {8, 1, ""}, {7, 1, ""}, {1, 1, ""}, {0, ^uint32(0), ""}, {6, 2, ""},
	} {
		p := unsafe.Add(unsafe.Pointer(&b[0]), test.offset)
		if got := windows.UTF16ToString(versionWords(b, p, test.units)); got != test.want {
			t.Fatalf("offset %d units %d: %q", test.offset, test.units, got)
		}
	}
	if versionWords(b, nil, 1) != nil || versionWords(nil, unsafe.Pointer(&b[0]), 1) != nil {
		t.Fatal("nil resource accepted")
	}
	// A pointer from a different allocation is never dereferenced.
	outside := make([]byte, 32)
	if versionWords(b, unsafe.Pointer(&outside[0]), 1) != nil {
		t.Fatal("foreign resource pointer accepted")
	}
}

func TestProgramFilesIgnoresSpoofedEnvironment(t *testing.T) {
	before, err := ProgramFiles()
	if err != nil || before == "" {
		t.Fatal(before, err)
	}
	t.Setenv("ProgramFiles", t.TempDir())
	after, err := ProgramFiles()
	if err != nil || after != before {
		t.Fatal(after, err)
	}
}

func hostedSecurity(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("hosted security proof requires elevation")
	}
}

func fileSecurity(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func TestMachineFolderQuarantinesUntrustedOwner(t *testing.T) {
	hostedSecurity(t)
	root := filepath.Join(t.TempDir(), "machine")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "untrusted"), []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	items, err := os.ReadDir(root)
	if err != nil || len(items) != 1 || items[0].Name() != directoryMarkerName {
		t.Fatalf("untrusted files retained: %v %v", items, err)
	}
	old, err := filepath.Glob(root + ".untrusted-*")
	if err != nil || len(old) != 1 {
		t.Fatal(old, err)
	}
	if b, err := os.ReadFile(filepath.Join(old[0], "untrusted")); err != nil || string(b) != "keep me" {
		t.Fatal(string(b), err)
	}
}

func TestMachineFolderRejectsHardlinkBeforeChangingOutsideACL(t *testing.T) {
	hostedSecurity(t)
	base := t.TempDir()
	root := filepath.Join(base, "machine")
	if err := ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	before := fileSecurity(t, outside)
	if err := ProtectDirectory(root); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatal(err)
	}
	if after := fileSecurity(t, outside); after != before {
		t.Fatalf("outside ACL changed: %s -> %s", before, after)
	}
}

func TestMachineFolderRefusesPreopenedWriter(t *testing.T) {
	hostedSecurity(t)
	root := filepath.Join(t.TempDir(), "machine")
	if err := ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(root)
	h, err := windows.CreateFile(p, windows.FILE_WRITE_DATA, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := ProtectDirectory(root); err == nil {
		t.Fatal("preopened directory writer was accepted")
	}
}
