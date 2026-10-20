package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
)

func ownerSessionPresent(owner string, _ uint32) (bool, error) {
	if owner == "" {
		return false, nil
	}
	uid, err := strconv.ParseUint(owner, 10, 32)
	if err != nil {
		return false, err
	}
	bus, err := dbus.SystemBus()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return logindOwnerPresent(ctx, uint32(uid), func(path dbus.ObjectPath) dbus.BusObject {
		return bus.Object("org.freedesktop.login1", path)
	})
}

func logindOwnerPresent(ctx context.Context, uid uint32, object func(dbus.ObjectPath) dbus.BusObject) (bool, error) {
	manager := object("/org/freedesktop/login1")
	var sessions []struct {
		ID         string
		UID        uint32
		User, Seat string
		Path       dbus.ObjectPath
	}
	if err := manager.CallWithContext(ctx, "org.freedesktop.login1.Manager.ListSessions", 0).Store(&sessions); err != nil {
		return false, fmt.Errorf("logind ListSessions: %w", err)
	}
	var uncertain error
	for _, session := range sessions {
		if session.UID != uid {
			continue
		}
		var state dbus.Variant
		err := object(session.Path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.login1.Session", "State").Store(&state)
		if err != nil {
			// ListSessions and Properties.Get are separate snapshots. A
			// session removed in between is absent, not an unavailable bus.
			if logindMissingObject(err, "org.freedesktop.login1.NoSuchSession") {
				continue
			}
			uncertain = errors.Join(uncertain, fmt.Errorf("logind session %s State: %w", session.ID, err))
			continue
		}
		switch state.Value() {
		case "active", "online", "opening":
			// Count both seatless SSH and inactive seats. Opening is emitted
			// by logind while a new session's scope is being created.
			return true, nil
		case "closing":
			// With KillUserProcesses=no, logged-out sessions can stay listed
			// indefinitely while nohup/tmux processes hold their scopes open.
		default:
			uncertain = errors.Join(uncertain, fmt.Errorf("logind session %s has invalid State %v", session.ID, state.Value()))
		}
	}
	var path dbus.ObjectPath
	if err := manager.CallWithContext(ctx, "org.freedesktop.login1.Manager.GetUser", 0, uid).Store(&path); err != nil {
		if logindErrorName(err) == "org.freedesktop.login1.NoSuchUser" {
			return false, uncertain
		}
		return false, errors.Join(uncertain, fmt.Errorf("logind GetUser: %w", err))
	}
	var linger dbus.Variant
	err := object(path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.login1.User", "Linger").Store(&linger)
	if err != nil {
		if logindMissingObject(err, "org.freedesktop.login1.NoSuchUser") {
			return false, uncertain
		}
		return false, errors.Join(uncertain, fmt.Errorf("logind user Linger: %w", err))
	}
	present, ok := linger.Value().(bool)
	if !ok {
		return false, errors.Join(uncertain, errors.New("logind returned an invalid Linger property"))
	}
	if present {
		return true, nil
	}
	// An unreadable owner session must not become a false logout just
	// because every other session closed and the user has no linger.
	return false, uncertain
}

func logindMissingObject(err error, name string) bool {
	got := logindErrorName(err)
	return got == name || got == "org.freedesktop.DBus.Error.UnknownObject"
}

func logindErrorName(err error) string {
	var reply dbus.Error
	if errors.As(err, &reply) {
		return reply.Name
	}
	var pointer *dbus.Error
	if errors.As(err, &pointer) {
		return pointer.Name
	}
	return ""
}
