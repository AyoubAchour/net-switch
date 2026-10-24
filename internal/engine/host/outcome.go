package host

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/sharedfile"
)

type Outcome struct {
	Child    *ChildOutcome `json:"child,omitempty"`
	Instance string        `json:"engineInstanceId"`
	State    string        `json:"state"` // running, pending, complete, failed
	Reason   string        `json:"reason,omitempty"`
	Error    string        `json:"error,omitempty"`
	// systemd can unload an inactive unit and forget ExecMainStatus. Only its
	// matching ExecStopPost invocation may supply the retained main result.
	InvocationID string       `json:"invocationId,omitempty"`
	BootID       string       `json:"bootId,omitempty"`
	Systemd      *SystemdExit `json:"systemd,omitempty"`
	// RecoveryPID is the process that ran the last journal recovery for this
	// instance: the host after its child exits, or the manager's recovery
	// command (SCM) / ExecStopPost (systemd). Tests use it to tell which
	// writer published the final result.
	RecoveryPID uint32 `json:"recoveryPid,omitempty"`
}

type ChildOutcome struct {
	HostHealthPasses   uint64 `json:"hostHealthPasses,omitempty"`
	HostHealthFailures uint64 `json:"hostHealthFailures,omitempty"`
	HostLogsDropped    uint64 `json:"hostLogsDropped,omitempty"`
	PID                uint32 `json:"pid"`
	Code               uint32 `json:"code"`
	Forced             bool   `json:"forced"`
	Completed          bool   `json:"completed"`
	Error              string `json:"error,omitempty"`
}

func OutcomePath(data, instance string) (string, error) {
	b, err := hex.DecodeString(instance)
	if err != nil || len(b) != 16 {
		return "", errors.New("invalid native outcome instance")
	}
	return filepath.Join(data, "engine-outcome-"+instance+".json"), nil
}

func ReadOutcome(data, instance string) (Outcome, error) {
	var result Outcome
	path, err := OutcomePath(data, instance)
	if err != nil {
		return result, err
	}
	b, err := sharedfile.ReadFile(path, 32<<10)
	if err != nil {
		return result, err
	}
	if len(b) > 32<<10 { // includes JSON escaping of the bounded 4096-byte error
		return result, errors.New("native outcome exceeds its bound")
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return result, err
	}
	if result.Instance != instance {
		return result, errors.New("native outcome instance mismatch")
	}
	if result.State != "running" && result.State != "pending" && result.State != "complete" && result.State != "failed" {
		return result, errors.New("invalid native cleanup state")
	}
	if result.State == "complete" && result.Error != "" {
		return result, errors.New("native cleanup reports both success and failure")
	}
	if result.InvocationID != "" && !ValidInvocationID(result.InvocationID) {
		return result, errors.New("invalid service invocation")
	}
	if result.BootID != "" && !ValidInvocationID(result.BootID) {
		return result, errors.New("invalid outcome boot identity")
	}
	if result.Systemd != nil && (!ValidInvocationID(result.InvocationID) || !result.Systemd.Valid()) {
		return result, errors.New("invalid retained systemd exit")
	}
	return result, nil
}

// Called under the native ownership lock at startup. A late result for an old
// instance has a different filename and cannot overwrite the new one's state.
func RetireOutcomes(data, keep string) error {
	entries, err := os.ReadDir(data)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "engine-outcome-"), ".json")
		path, err := OutcomePath(data, id)
		if err != nil || filepath.Base(path) != entry.Name() || id == keep {
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

type borrowedLock struct{}

func (borrowedLock) Acquire(context.Context) (func() error, error) {
	return func() error { return nil }, nil
}

// Recover holds exactly the platform's existing ownership lock. begin captures
// the failed instance under that lock; its writer uses an instance-specific
// outcome file after ALL closes, including lock release, have completed.
func Recover(ctx context.Context, lock journal.Locker, run func(journal.Locker) error, begin func() (func(error) error, error)) error {
	release, err := lock.Acquire(ctx)
	if err != nil {
		return err
	}
	finish, err := begin()
	if err != nil {
		return errors.Join(err, release())
	}
	err = run(borrowedLock{})
	err = errors.Join(err, release())
	if finish != nil {
		err = errors.Join(err, finish(err))
	}
	return err
}
