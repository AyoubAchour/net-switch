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

// Hosted Windows actors have real tokens but no WTS desktop. This explicit
// fixture substitutes only their session presence, never their IPC identity.
func OwnerSession(data, user string) (bool, bool) {
	b, err := os.ReadFile(filepath.Join(data, "fault-owner-sessions.json"))
	if err != nil {
		return false, false
	}
	var sessions map[string]bool
	if json.Unmarshal(b, &sessions) != nil {
		return false, false
	}
	present, known := sessions[user]
	return present, known
}

// ProbeSession exercises the real query with the installed service's token.
// Unlike OwnerSession this observes the OS and does not inject a result.
func ProbeSession(data string, query func(string, uint32) (bool, error)) error {
	b, err := os.ReadFile(filepath.Join(data, "fault-real-session.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var owner string
	if err := json.Unmarshal(b, &owner); err != nil {
		return err
	}
	present, queryErr := query(owner, ^uint32(0))
	message := ""
	if queryErr != nil {
		message = queryErr.Error()
	}
	b, err = json.Marshal(map[string]any{"pid": os.Getpid(), "owner": owner, "present": present, "error": message})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(data, "fault-real-session-result.json"), b, 0600)
}
