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

func TestStartupLeavesProtectedMachineCreationAndRecoveryToWorker(t *testing.T) {
	base := t.TempDir()
	user, machine := filepath.Join(base, "user"), filepath.Join(base, "machine")
	if err := prepareDataDirectories(user, machine, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(machine); !os.IsNotExist(err) {
		t.Fatal("startup recreated the protected machine folder before migration recovery", err)
	}
	if _, err := os.Stat(user); err != nil {
		t.Fatal(err)
	}
	if err := prepareDataDirectories(user, machine, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(machine); err != nil {
		t.Fatal("development data directory missing", err)
	}
}
