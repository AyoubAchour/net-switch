//go:build linux

package linux

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFlatpakMetadataConfinement(t *testing.T) {
	for _, kind := range []string{"regular", "exact-limit", "oversize", "sparse", "symlink-zero", "symlink-file", "magic-link", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".flatpak-info")
			want := []byte("[Application]\nname=org.example.App\n")
			var err error
			switch kind {
			case "regular":
				err = os.WriteFile(path, want, 0600)
			case "exact-limit", "oversize":
				n := 64 << 10
				if kind == "oversize" {
					n++
				}
				want = bytes.Repeat([]byte{'x'}, n)
				err = os.WriteFile(path, want, 0600)
			case "sparse":
				var f *os.File
				f, err = os.Create(path)
				if err == nil {
					err = f.Truncate(1 << 40)
					f.Close()
				}
			case "symlink-zero":
				err = os.Symlink("/dev/zero", path)
			case "symlink-file":
				other := filepath.Join(root, "metadata")
				if err = os.WriteFile(other, want, 0600); err == nil {
					err = os.Symlink("metadata", path)
				}
			case "magic-link":
				err = os.Symlink("/proc/self/fd/0", path)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			got, err := readFlatpakInfo(root, make([]byte, 64<<10))
			if time.Since(start) > time.Second {
				t.Fatal("metadata read blocked")
			}
			if kind == "regular" || kind == "exact-limit" {
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("legitimate metadata: %d bytes, %v", len(got), err)
				}
			} else if err == nil || len(got) != 0 {
				t.Fatalf("unsafe metadata accepted: %d bytes, %v", len(got), err)
			}
		})
	}
}

func TestKernelReadsRejectSpecialFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, read := range []func(string) ([]byte, error){
		func(p string) ([]byte, error) { return readInto(p, make([]byte, 128)) },
		func(p string) ([]byte, error) { return readKernelFile(p, 128) },
	} {
		if _, err := read(path); !errors.Is(err, errNotRegular) {
			t.Fatalf("FIFO: %v", err)
		}
		if _, err := read("/dev/zero"); !errors.Is(err, errNotRegular) {
			t.Fatalf("device: %v", err)
		}
	}
}

func TestLargeFlatpakEnvironmentKeepsCompleteIdentity(t *testing.T) {
	root := t.TempDir()
	identity := []byte("[Application]\nname=org.example.LargeEnvironment\n")
	data := append(bytes.Clone(identity), []byte("[Environment]\nPAD="+string(bytes.Repeat([]byte{'x'}, 70000)))...)
	if err := os.WriteFile(filepath.Join(root, ".flatpak-info"), data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readFlatpakInfo(root, make([]byte, 64<<10))
	if err != nil || !bytes.Equal(got, identity) {
		t.Fatalf("bounded identity: %q %v", got, err)
	}
	// A name beginning before the boundary but ending after it is not proof.
	data = append([]byte("[Application]\nname="), bytes.Repeat([]byte{'x'}, 70000)...)
	if err := os.WriteFile(filepath.Join(root, ".flatpak-info"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readFlatpakInfo(root, make([]byte, 64<<10)); !errors.Is(err, errKernelFileLimit) || len(got) != 0 {
		t.Fatalf("truncated identity accepted: %d %v", len(got), err)
	}
}

func TestDescriptorInspectionDoesNotTurnErrorsIntoAbsence(t *testing.T) {
	dir, err := openProcDescriptors("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if _, ok, err := socketInodeAtChecked(dir.fd, "2147483647"); ok || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing descriptor was not explicit: found=%t error=%v", ok, err)
	}
	if _, ok, err := socketInodeAtChecked(-999, "3"); ok || !errors.Is(err, unix.EBADF) {
		t.Fatalf("failed inspection became an ordinary non-socket result: found=%t error=%v", ok, err)
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, ok, err := socketInodeAtChecked(dir.fd, strconv.FormatUint(uint64(file.Fd()), 10)); ok || err != nil {
		t.Fatalf("readable non-socket descriptor was treated as an inspection failure: found=%t error=%v", ok, err)
	}
}
