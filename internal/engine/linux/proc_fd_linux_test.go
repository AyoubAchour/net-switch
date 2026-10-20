//go:build linux

package linux

import (
	"errors"
	"io"
	"os"
	"strconv"
	"testing"
)

func TestProcDescriptorWindowsKeepEntriesAndReuseStorage(t *testing.T) {
	var files []*os.File
	want := map[int]int{}
	for range 80 {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files = append(files, f)
		want[int(f.Fd())] = 0
	}
	dir, err := openProcDescriptors("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for {
		n, err := dir.Visit(7, func(name []byte) bool {
			fd, err := strconv.Atoi(string(name))
			if err != nil {
				t.Errorf("non-descriptor proc entry %q", name)
				return false
			}
			if _, ok := want[fd]; ok {
				want[fd]++
			}
			return true
		})
		if n > 7 {
			t.Fatalf("read %d entries past the requested window", n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for fd, count := range want {
		if count != 1 {
			t.Fatalf("descriptor %d appeared %d times across windows", fd, count)
		}
	}
	target := int(files[50].Fd())
	got, read := -1, 0
	var seekErr, readErr error
	allocs := testing.AllocsPerRun(100, func() {
		_, seekErr = dir.Seek(int64(target)+2, 0)
		read, readErr = dir.Visit(1, func(name []byte) bool { got, _ = strconv.Atoi(string(name)); return true })
	})
	if seekErr != nil || readErr != nil || read != 1 || got != target {
		t.Fatalf("seek to fd %d: got %d, read %d, errors %v %v", target, got, read, seekErr, readErr)
	}
	if allocs != 0 {
		t.Fatalf("seek and targeted descriptor visit allocated %.1f objects", allocs)
	}
}
