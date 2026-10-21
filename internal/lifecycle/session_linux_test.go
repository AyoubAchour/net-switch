package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type logindTestObject struct {
	dbus.BusObject
	call func(context.Context, string, dbus.Flags, ...any) *dbus.Call
}

func (o logindTestObject) CallWithContext(ctx context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
	return o.call(ctx, method, flags, args...)
}

func TestLogindClosingOwnerIsAbsent(t *testing.T) {
	f := logindFixture{sessions: []logindTestSession{{uid: 1000, state: "closing"}}}
	present, err := f.query(t)
	if err != nil || present {
		t.Fatalf("logged-out owner with closing scope and linger disabled: present=%v err=%v; want absent", present, err)
	}
}

type logindTestSession struct {
	uid      uint32
	seat     string
	state    any
	err      error
	class    any
	classErr error
}

type logindFixture struct {
	sessions                    []logindTestSession
	listErr, userErr, lingerErr error
	linger                      any
	malformedList               bool
}

func (f logindFixture) query(t *testing.T) (bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	const manager = dbus.ObjectPath("/org/freedesktop/login1")
	const user = dbus.ObjectPath("/org/freedesktop/login1/user/_1000")
	rows := make([][]any, len(f.sessions))
	states := make(map[dbus.ObjectPath]logindTestSession)
	for i, session := range f.sessions {
		id := fmt.Sprintf("c%d", i+1)
		path := dbus.ObjectPath("/org/freedesktop/login1/session/" + id)
		rows[i] = []any{id, session.uid, "user", session.seat, path}
		states[path] = session
	}
	object := func(path dbus.ObjectPath) dbus.BusObject {
		return logindTestObject{call: func(gotCtx context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
			if gotCtx != ctx || flags != 0 {
				t.Fatal("logind calls must share the bounded query context")
			}
			switch {
			case path == manager && method == "org.freedesktop.login1.Manager.ListSessions" && len(args) == 0:
				if f.malformedList {
					return &dbus.Call{Body: []any{"invalid sessions"}}
				}
				return &dbus.Call{Body: []any{rows}, Err: f.listErr}
			case path == manager && method == "org.freedesktop.login1.Manager.GetUser" && reflect.DeepEqual(args, []any{uint32(1000)}):
				return &dbus.Call{Body: []any{user}, Err: f.userErr}
			case path == user && method == "org.freedesktop.DBus.Properties.Get" && reflect.DeepEqual(args, []any{"org.freedesktop.login1.User", "Linger"}):
				linger := f.linger
				if linger == nil {
					linger = false
				}
				return &dbus.Call{Body: []any{dbus.MakeVariant(linger)}, Err: f.lingerErr}
			case method == "org.freedesktop.DBus.Properties.Get" && reflect.DeepEqual(args, []any{"org.freedesktop.login1.Session", "State"}):
				session, ok := states[path]
				if !ok || session.uid != 1000 {
					t.Fatalf("queried unknown or non-owner session: %s", path)
				}
				if session.err != nil {
					return &dbus.Call{Err: session.err}
				}
				return &dbus.Call{Body: []any{dbus.MakeVariant(session.state)}}
			case method == "org.freedesktop.DBus.Properties.Get" && reflect.DeepEqual(args, []any{"org.freedesktop.login1.Session", "Class"}):
				session, ok := states[path]
				if !ok || session.uid != 1000 {
					t.Fatalf("queried unknown or non-owner session class: %s", path)
				}
				class := session.class
				if class == nil {
					class = "user"
				}
				return &dbus.Call{Body: []any{dbus.MakeVariant(class)}, Err: session.classErr}
			default:
				t.Fatalf("unexpected logind call %s %s %v", path, method, args)
				return nil
			}
		}}
	}
	return logindOwnerPresent(ctx, 1000, object)
}

func TestLogindOwnerPresenceStatesAndErrors(t *testing.T) {
	closing := logindTestSession{uid: 1000, state: "closing"}
	active := logindTestSession{uid: 1000, seat: "seat0", state: "active"}
	online := logindTestSession{uid: 1000, seat: "seat0", state: "online"}
	opening := logindTestSession{uid: 1000, state: "opening"}
	missing := dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}
	noUser := dbus.Error{Name: "org.freedesktop.login1.NoSuchUser"}
	unavailable := logindTestSession{uid: 1000, err: context.DeadlineExceeded}
	for _, tt := range []struct {
		name    string
		fixture logindFixture
		present bool
		errText string
	}{
		{name: "no sessions"},
		{name: "active desktop", fixture: logindFixture{sessions: []logindTestSession{active}}, present: true},
		{name: "seatless SSH", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "active"}}}, present: true},
		{name: "online inactive seat", fixture: logindFixture{sessions: []logindTestSession{online}}, present: true},
		{name: "opening scope", fixture: logindFixture{sessions: []logindTestSession{opening}}, present: true},
		{name: "all owner sessions closing", fixture: logindFixture{sessions: []logindTestSession{closing, closing}}},
		{name: "closing with online manager", fixture: logindFixture{sessions: []logindTestSession{closing, {uid: 1000, state: "online", class: "manager"}}}},
		{name: "closing with active manager", fixture: logindFixture{sessions: []logindTestSession{closing, {uid: 1000, state: "active", class: "manager"}}}},
		{name: "closing with opening manager", fixture: logindFixture{sessions: []logindTestSession{closing, {uid: 1000, state: "opening", class: "manager"}}}},
		{name: "manager early only", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "online", class: "manager-early"}}}},
		{name: "manager with real login", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "online", class: "manager"}, active}}, present: true},
		{name: "manager with linger", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "online", class: "manager"}}, linger: true}, present: true},
		{name: "class lookup failed", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "online", classErr: context.DeadlineExceeded}}}, errText: "Class"},
		{name: "class disappeared", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "online", classErr: missing}}}},
		{name: "invalid class", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "online", class: true}}}, errText: "Class"},
		{name: "another owner session online", fixture: logindFixture{sessions: []logindTestSession{closing, online}}, present: true},
		{name: "non-owner stays active", fixture: logindFixture{sessions: []logindTestSession{closing, {uid: 1001, state: "active"}}}},
		{name: "non-owner query would fail", fixture: logindFixture{sessions: []logindTestSession{{uid: 1001, err: context.DeadlineExceeded}, online}}, present: true},
		{name: "linger without sessions", fixture: logindFixture{linger: true}, present: true},
		{name: "linger after logout", fixture: logindFixture{sessions: []logindTestSession{closing}, linger: true}, present: true},
		{name: "session disappeared", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, err: missing}}}},
		{name: "NoSuchSession", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, err: dbus.Error{Name: "org.freedesktop.login1.NoSuchSession"}}}}},
		{name: "wrapped pointer disappearance", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, err: errors.Join(&missing)}}}},
		{name: "disappeared then online", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, err: missing}, online}}, present: true},
		{name: "missing user", fixture: logindFixture{userErr: noUser}},
		{name: "user disappeared before linger", fixture: logindFixture{lingerErr: missing}},
		{name: "NoSuchUser before linger", fixture: logindFixture{lingerErr: &noUser}},
		{name: "list unavailable", fixture: logindFixture{listErr: context.DeadlineExceeded}, errText: "ListSessions"},
		{name: "malformed list", fixture: logindFixture{malformedList: true}, errText: "ListSessions"},
		{name: "state unavailable", fixture: logindFixture{sessions: []logindTestSession{unavailable}}, errText: "session c1 State"},
		{name: "one unknown and one closing", fixture: logindFixture{sessions: []logindTestSession{closing, unavailable}}, errText: "session c2 State"},
		{name: "unknown then active", fixture: logindFixture{sessions: []logindTestSession{unavailable, active}}, present: true},
		{name: "unknown with linger", fixture: logindFixture{sessions: []logindTestSession{unavailable}, linger: true}, present: true},
		{name: "unknown with missing user", fixture: logindFixture{sessions: []logindTestSession{unavailable}, userErr: noUser}, errText: "session c1 State"},
		{name: "unknown with disappearing user", fixture: logindFixture{sessions: []logindTestSession{unavailable}, lingerErr: missing}, errText: "session c1 State"},
		{name: "unknown state", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: "future-state"}}}, errText: "invalid State"},
		{name: "invalid state type", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, state: true}}}, errText: "invalid State"},
		{name: "missing property is uncertainty", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, err: dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownProperty"}}}}, errText: "State"},
		{name: "access denied is uncertainty", fixture: logindFixture{sessions: []logindTestSession{{uid: 1000, err: dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}}}}, errText: "State"},
		{name: "missing manager is uncertainty", fixture: logindFixture{userErr: missing}, errText: "GetUser"},
		{name: "linger unavailable", fixture: logindFixture{lingerErr: context.DeadlineExceeded}, errText: "Linger"},
		{name: "invalid linger", fixture: logindFixture{linger: "false"}, errText: "invalid Linger"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			present, err := tt.fixture.query(t)
			if present != tt.present || (err != nil) != (tt.errText != "") {
				t.Fatalf("present=%v err=%v; want present=%v error containing %q", present, err, tt.present, tt.errText)
			}
			if err != nil && !strings.Contains(err.Error(), tt.errText) {
				t.Fatalf("error %q lacks diagnostic %q", err, tt.errText)
			}
		})
	}
}

func TestLogindRetainsAllQueryFailures(t *testing.T) {
	denied := errors.New("permission denied")
	f := logindFixture{sessions: []logindTestSession{{uid: 1000, err: context.DeadlineExceeded}}, lingerErr: denied}
	present, err := f.query(t)
	if present || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, denied) {
		t.Fatal("session and linger errors must remain visible", present, err)
	}
}

func TestLinuxOwnerIdentityBeforeBus(t *testing.T) {
	for _, owner := range []string{"", "invalid", "-1", "4294967296"} {
		present, err := ownerSessionPresent(owner, 0)
		if present || (err == nil) != (owner == "") {
			t.Fatalf("owner=%q present=%v err=%v", owner, present, err)
		}
	}
}
