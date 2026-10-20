//go:build windows && netswitch_handlecheck

package winhandle

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCloseAndUseTripwireSurvivesHandleValueReuse(t *testing.T) {
	r := &registry{values: map[windows.Handle]*entry{}}
	const value = windows.Handle(0xfeed)
	old := Owner{value, r.open(value, "first open")}
	r.use(old, "first operation", false)
	r.close(old, "first close", false)
	fresh := Owner{value, r.open(value, "reused value")}
	r.finish(old, "first close returned", nil)
	r.use(fresh, "new owner's operation", false)
	for _, scenario := range []struct {
		name string
		call func()
	}{
		{"old close", func() { r.close(old, "stale closer", false) }},
		{"old operation", func() { r.use(old, "stale reader", false) }},
		{"second owner", func() { r.open(value, "duplicate owner") }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			defer func() {
				recovered := recover()
				if recovered == nil || !strings.Contains(recovered.(string), "WINDOWS HANDLE OWNERSHIP VIOLATION") {
					t.Fatalf("tripwire did not identify %s: %v", scenario.name, recovered)
				}
			}()
			scenario.call()
		})
	}
	r.close(fresh, "new owner close", false)
	r.finish(fresh, "new owner close", nil)
}

func TestGoBorrowRemainsValidWhileCloseWaitsForItsReference(t *testing.T) {
	r := &registry{values: map[windows.Handle]*entry{}}
	owner := Owner{0xfeed, r.open(0xfeed, "Go open")}
	r.close(owner, "Go Close pending", true)
	r.use(owner, "inside RawConn.Control", true)
	r.finish(owner, "Go Close returned", nil)
	defer func() {
		if recover() == nil {
			t.Fatal("a completed Go close left its generation usable")
		}
	}()
	r.use(owner, "late borrowed value", true)
}

func TestDriverOwnedHandleCanBeRecycledWithoutAnotherUserClose(t *testing.T) {
	const value = windows.Handle(0xface)
	old := OpenDriverHandle(value, "driver device open")
	fresh := Open(value, "fresh OS allocation after driver removal")
	old.DriverReleased("driver final marker observed")
	fresh.Handle("fresh owner remains valid")
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("driver removal licensed closing the recycled handle")
			}
		}()
		old.Close("stale driver close", func(windows.Handle) error {
			t.Fatal("stale close reached Windows")
			return nil
		})
	}()
	fresh.Close("fresh owner close", func(windows.Handle) error { return nil })
}
