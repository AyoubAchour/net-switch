package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

func runNativeChild(ctx context.Context, ready func(), c Config, log func(string), configure func(*host.Options)) error {
	run, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	instance := ""
	boot, err := host.CurrentBootID()
	if err != nil {
		return err
	}
	invocation := ""
	if runtime.GOOS == "linux" && host.ValidInvocationID(os.Getenv("INVOCATION_ID")) {
		invocation = os.Getenv("INVOCATION_ID")
	}
	var server *protocol.Server
	options := host.Options{
		Progress: func(stage string) { log("native startup: " + stage) },
		OpenState: func(id string) (host.State, error) {
			instance = id
			if err := host.RetireOutcomes(c.Data, id); err != nil {
				return nil, err
			}
			path := filepath.Join(c.Data, "engine-state.json")
			state, err := host.Open(path, id, func(record host.Record) error { return saveNative(path, record) })
			if err != nil {
				return nil, err
			}
			return state, writeOutcome(c.Data, host.Outcome{Instance: id, State: "running", InvocationID: invocation, BootID: boot})
		},
		Ready: func(s *protocol.Server) {
			server = s
			workers.Go(func() {
				events := service.Events(ctx)
				for {
					select {
					case <-run.Done():
						return
					case <-events.Ready():
						for _, event := range events.Take() {
							if event.Resume {
								resumeEngine(server, log)
							}
						}
					}
				}
			})
			ready()
		},
	}
	if err := configureNativeProof(c.Data, &options); err != nil {
		return err
	}
	configure(&options)
	// Native Serve owns the OS lifetime lock and cleanup. Acquiring the old
	// adapter lock here would deadlock Linux startup on the same engine.lock.
	err = serveNative(run, c.Data, options)
	if err == nil {
		err = nativeProofExit(c.Data)
	}
	if instance != "" {
		out := host.Outcome{Instance: instance, State: "pending", Reason: "stop", InvocationID: invocation, BootID: boot}
		if server != nil && server.LeaseExpired() {
			out.Reason = "lease-expired"
		}
		if service.ExitCode(err) == 3 {
			out.Reason = "adapter lost"
		} else if err != nil {
			out.Reason = "failure"
			out.Error = err.Error()
		}
		if runtime.GOOS == "windows" && err == nil {
			out.State = "complete"
		}
		if saveErr := writeOutcome(c.Data, out); saveErr != nil {
			return errors.Join(err, saveErr)
		}
		log("native outcome instance=" + instance + " reason=" + out.Reason + " cleanup=" + out.State + " error=" + out.Error)
	}
	return err
}

func writeOutcome(data string, out host.Outcome) error {
	path, err := host.OutcomePath(data, out.Instance)
	if err != nil {
		return err
	}
	if len(out.Error) > 4096 {
		out.Error = out.Error[:4096]
	}
	if out.Child != nil && len(out.Child.Error) > 1024 {
		out.Child.Error = out.Child.Error[:1024]
	}
	return saveNative(path, out)
}

// Capture the instance while owning its native lifetime lock, then write to
// that instance's own result file after cleanup and the final release.
func recoveryOutcome(data string) (func(error) error, error) {
	record, err := host.ReadRecord(filepath.Join(data, "engine-state.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out, err := host.ReadOutcome(data, record.Instance)
	if os.IsNotExist(err) {
		out = host.Outcome{Instance: record.Instance}
	} else if err != nil {
		return nil, err
	}
	if runtime.GOOS == "linux" {
		captureSystemdExit(&out, os.Getenv)
	}
	out.State, out.Error = "pending", ""
	out.RecoveryPID = uint32(os.Getpid())
	if err := writeOutcome(data, out); err != nil {
		return nil, err
	}
	finish := func(cleanup error) error {
		out.State = "complete"
		if cleanup != nil {
			out.State = "failed"
			out.Error = cleanup.Error()
		}
		return writeOutcome(data, out)
	}
	if injected := nativeProofRecovery(data); injected != nil {
		return nil, errors.Join(injected, finish(injected))
	}
	return finish, nil
}

// Native history has one atomic durable replacement. No unread backup can
// turn a successful primary commit into a reported failure.
func saveNative(path string, value any) error {
	return saveNativeWith(path, value, settings.Options{Files: nativeStateFiles{}, SyncFile: syncFile, SyncParent: SyncDirectory})
}

type nativeStateFiles struct{ durableFiles }

func (nativeStateFiles) Rename(from, to string) error { return replaceNativeState(from, to) }

func saveNativeWith(path string, value any, options settings.Options) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return settings.AtomicWrite(path, b, options)
}
