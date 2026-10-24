package lifecycle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func arm(t *testing.T, data, point string) {
	t.Helper()
	err := os.Remove(filepath.Join(data, "fault-hit.json"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "fault-"+point), []byte("hosted test only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(filepath.Join(data, "fault-"+point)); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	})
}
func barrier(t *testing.T, data, point string) uint32 {
	t.Helper()
	var hit struct {
		PID   uint32 `json:"pid"`
		Point string `json:"point"`
	}
	wait(t, "crash barrier "+point, 20*time.Second, func() bool {
		return lifecycle.Read(filepath.Join(data, "fault-hit.json"), &hit) == nil && hit.Point == point
	})
	if hit.PID == 0 {
		t.Fatal("barrier has no process")
	}
	return hit.PID
}
func mutateAsync(url, token, label string) <-chan error {
	return actionAsync(url, token, "api/lines/update", `{"id":"a1","label":"`+label+`"}`)
}
func actionAsync(url, token, route, body string) <-chan error {
	done := make(chan error, 1)
	go func() {
		r, err := http.NewRequest("POST", url+route, strings.NewReader(body))
		if err != nil {
			done <- err
			return
		}
		r.Header.Set("X-Token", token)
		r.Header.Set("Content-Type", "application/json")
		response, err := apiClient(35 * time.Second).Do(r)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				done <- nil
				return
			}
			err = fmt.Errorf("interrupted mutation returned %d", response.StatusCode)
		}
		done <- err
	}()
	return done
}

// checkAppliedJournal proves Control's durable desired revision is the one the
// engine has committed: the native record keeps the engine's own hash of the
// compiled config, so the comparison is on the revision number and on the
// hash Control would send for that same desired policy.
func checkAppliedJournal(t *testing.T, data, label string) {
	t.Helper()
	var desired struct {
		Desired ce.Revision `json:"desired"`
	}
	var state struct {
		Instance string `json:"engineInstanceId"`
		N        uint64 `json:"n"`
		Hash     string `json:"hash"`
	}
	wait(t, "desired revision acknowledged", 25*time.Second, func() bool {
		if lifecycle.Read(filepath.Join(data, "control-journal.json"), &desired) != nil || lifecycle.Read(filepath.Join(data, "engine-state.json"), &state) != nil {
			return false
		}
		native, err := lifecycle.NativeRevision(desired.Desired)
		return err == nil && desired.Desired.Number == state.N && native.Hash == state.Hash &&
			len(desired.Desired.Policy.Lines) == 1 && desired.Desired.Policy.Lines[0].Label == label
	})
}
func durableCrash(t *testing.T, ctx context.Context, data, point, url, token string, fixture tunFixture, owner actor) *client {
	t.Helper()
	before, err := service.Query(service.Control)
	if err != nil {
		t.Fatal(err)
	}
	stream := routedStream(t, ctx, fixture)
	defer stream.Close()
	fixture.exchange(t, stream)
	var previousEngine struct {
		Instance string `json:"engineInstanceId"`
	}
	if err := lifecycle.Read(filepath.Join(data, "engine-state.json"), &previousEngine); err != nil {
		t.Fatal(err)
	}
	arm(t, data, point)
	label := point
	pending := mutateAsync(url, token, label)
	pid := barrier(t, data, point)
	var journal struct {
		Desired ce.Revision `json:"desired"`
	}
	if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal); err != nil || len(journal.Desired.Policy.Lines) != 1 || journal.Desired.Policy.Lines[0].Label != label {
		t.Fatal("barrier did not follow the requested durable change", err)
	}
	kill(t, pid)
	select {
	case err := <-pending:
		if err == nil {
			t.Fatal("interrupted operation was acknowledged")
		}
	case <-time.After(40 * time.Second):
		t.Fatal("interrupted HTTP request did not finish")
	}
	if strings.HasPrefix(point, "control-") {
		fixture.exchange(t, stream)
		wait(t, "Control recovery after journal interruption", 25*time.Second, func() bool {
			s, err := service.Query(service.Control)
			return err == nil && s.Running && s.PID != before.PID
		})
	} else {
		expectClosed(t, stream)
		directTraffic(t, ctx, fixture)
	}
	c := openClient(t, owner, false)
	wait(t, "routing recovers after durable interruption", 35*time.Second, func() bool {
		s := getStatus(t, c)
		return s.Routing == "on" && (strings.HasPrefix(point, "control-") || s.Instance != previousEngine.Instance)
	})
	checkAppliedJournal(t, data, label)
	if strings.HasPrefix(point, "control-") {
		fixture.exchange(t, stream)
	}
	return c
}

// replayClosure plants a closure intent whose cutoff is a revision Control has
// not acknowledged yet, applies that revision as the controller itself, then
// lets two successive Controls replay the same operation id: the old flow
// closes once, the newer flow (admitted after the apply point) survives both.
func replayClosure(t *testing.T, ctx context.Context, data string, fixture tunFixture, owner actor) *client {
	t.Helper()
	old := routedStream(t, ctx, fixture)
	defer old.Close()
	fixture.exchange(t, old)
	restore := disableRecovery(t)
	control, err := service.Query(service.Control)
	if err != nil {
		t.Fatal(err)
	}
	kill(t, control.PID)
	wait(t, "Control stopped before replay fixture", 10*time.Second, func() bool { s, err := service.Query(service.Control); return err == nil && !s.Running })
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	connection, err := localipc.DialNativeEngine(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
	if err != nil {
		t.Fatal(err)
	}
	rpc := lifecycle.NewRPC(connection)
	defer rpc.Close()
	var hello struct {
		Instance string          `json:"engineInstanceId"`
		Status   protocol.Status `json:"status"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		t.Fatal(err)
	}
	if hello.Status.Applied == nil {
		t.Fatal("engine has no loaded revision to build on", hello.Status)
	}
	var lease struct {
		Epoch uint64 `json:"epoch"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "attach", "engineInstanceId": hello.Instance}, &lease); err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &record); err != nil {
		t.Fatal(err)
	}
	var revision ce.Revision
	if err := json.Unmarshal(record["desired"], &revision); err != nil {
		t.Fatal(err)
	}
	revision.Number = max(revision.Number, hello.Status.Applied.N) + 1
	record["desired"], _ = json.Marshal(revision)
	record["revision"], _ = json.Marshal(revision.Number)
	record["engineInstanceId"], _ = json.Marshal(hello.Instance)
	intent := map[string]any{"intentId": "hosted-fixed-cutoff", "revision": revision.Number, "purpose": "reconnect", "request": ce.CloseRequest{
		OperationID: "hosted-fixed-cutoff", Instance: hello.Instance, Line: "a1", BeforeRevision: revision.Number,
	}}
	record["closures"], _ = json.Marshal([]any{intent})
	if err := lifecycle.Save(filepath.Join(data, "control-journal.json"), record); err != nil {
		t.Fatal(err)
	}
	native, err := lifecycle.NativeRevision(revision)
	if err != nil {
		t.Fatal(err)
	}
	var applied policy.Applied
	if err := rpc.Call(ctx, map[string]any{"method": "apply", "engineInstanceId": hello.Instance, "epoch": lease.Epoch, "revision": native}, &applied); err != nil {
		t.Fatal(err)
	}
	if applied.N != native.N || applied.Point == 0 {
		t.Fatal("engine did not return a fixed apply point", applied)
	}
	newer := routedStream(t, ctx, fixture)
	defer newer.Close()
	fixture.exchange(t, newer)
	rpc.Close()
	// Lose the close acknowledgement after its effect, then let another Control
	// replay the very same opId and revision cutoff.
	arm(t, data, "control-after-close-ack")
	restore()
	started := make(chan error, 1)
	go func() { started <- service.Start(ctx, service.Control) }()
	pid := barrier(t, data, "control-after-close-ack")
	expectClosed(t, old)
	fixture.exchange(t, newer)
	kill(t, pid)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	wait(t, "second closure replay", 25*time.Second, func() bool { s, err := service.Query(service.Control); return err == nil && s.Running && s.PID != pid })
	c := openClient(t, owner, false)
	wait(t, "closure completion durable", 10*time.Second, func() bool {
		var journal struct {
			Closures []json.RawMessage `json:"closures"`
		}
		return lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal) == nil && len(journal.Closures) == 0
	})
	fixture.exchange(t, newer)
	return c
}
