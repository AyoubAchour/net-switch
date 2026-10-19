package winplatform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	if err != nil || len(items) != 0 {
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
