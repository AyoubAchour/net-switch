//go:build lifecycle_test

// Package faultpoint supplies one-shot crash barriers to the hosted lifecycle
// suite. The arm file is in the administrator-only service store. These barriers
// are absent from normal builds and cannot be enabled through either API.
package faultpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func Hit(data, point string) {
	path := filepath.Join(data, "fault-"+point)
	if err := os.Rename(path, path+".consumed"); err != nil {
		return
	}
	b, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "point": point})
	f, err := os.OpenFile(filepath.Join(data, "fault-hit.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	if _, err = f.Write(b); err != nil {
		panic(err)
	}
	if err = f.Sync(); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}
	select {} // the test kills this exact process after verifying the barrier
}
