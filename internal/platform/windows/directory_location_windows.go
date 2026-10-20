package winplatform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/wintrust"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ResolveMachineDirectory reads only the protected HKLM mapping. A recorded
// physical store is authenticated on every resolution, never repaired in place.
func ResolveMachineDirectory(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	key, err := openDirectoryCertificates(false)
	if errors.Is(err, registry.ErrNotExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	target, _, err := key.GetStringValue("store-" + directoryCertificateName(path))
	if errors.Is(err, registry.ErrNotExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) || !strings.EqualFold(filepath.Dir(target), filepath.Dir(path)) || !strings.HasPrefix(strings.ToLower(target), strings.ToLower(path)+".store-") {
		return "", errors.New("invalid machine store location record")
	}
	if err := VerifyDirectory(target); err != nil {
		return "", err
	}
	return target, nil
}

func PrepareMachineDirectory(path string) (string, error) {
	return prepareMachineDirectory(path, nil)
}

func prepareMachineDirectory(path string, beforePublish func(string) error) (string, error) {
	resolved, err := ResolveMachineDirectory(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(resolved, path) {
		return resolved, nil
	}
	// Reusing a certified live store needs no exclusive ACL/migration work.
	// In particular, an engine lock held by our own running service is not a
	// hostile occupant and must not cause a new location to be published.
	if err := VerifyDirectory(path); err == nil {
		return path, nil
	}
	// Validate ancestors before touching a candidate or choosing a new name.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if err := wintrust.Path(parent, true); err != nil {
			return "", err
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	if err = ProtectDirectory(path); err == nil {
		return path, nil
	}
	// A previous certificate may describe a staged migration whose rename
	// was blocked by this very occupant. It must not turn a retry after a
	// crash into a permanent lockout. Retain the original and any stage;
	// never import their contents into the independently certified fallback.
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return "", e
	}
	fresh := path + ".store-" + hex.EncodeToString(nonce[:])
	if e := ProtectDirectory(fresh); e != nil {
		return "", errors.Join(err, e)
	}
	if e := VerifyDirectory(fresh); e != nil {
		return "", e
	}
	if beforePublish != nil {
		if e := beforePublish(fresh); e != nil {
			return "", e
		}
	}
	key, e := openDirectoryCertificates(true)
	if e != nil {
		return "", e
	}
	defer key.Close()
	if e = key.SetStringValue("store-"+directoryCertificateName(path), fresh); e != nil {
		return "", e
	}
	code, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey").Call(uintptr(key))
	if code != 0 {
		return "", windows.Errno(code)
	}
	fmt.Printf("original machine folder could not be quarantined; protected store created at %s\n", fresh)
	return fresh, nil
}
