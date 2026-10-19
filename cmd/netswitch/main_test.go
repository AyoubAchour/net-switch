package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRootIsExecutableFolderEvenFromAnotherDirectory(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	root, err := applicationRoot("", exe)
	if err != nil || root != filepath.Dir(exe) {
		t.Fatalf("default root %s: %v", root, err)
	}
	cwd, _ := os.Getwd()
	root, err = applicationRoot("override", exe)
	if err != nil || root != filepath.Join(cwd, "override") {
		t.Fatalf("override root %s: %v", root, err)
	}
}
