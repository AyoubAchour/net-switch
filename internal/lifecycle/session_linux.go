package lifecycle

import (
	"context"
	"errors"
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
	manager := bus.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	var sessions []struct {
		ID         string
		UID        uint32
		User, Seat string
		Path       dbus.ObjectPath
	}
	if err := manager.CallWithContext(ctx, "org.freedesktop.login1.Manager.ListSessions", 0).Store(&sessions); err != nil {
		return false, err
	}
	for _, session := range sessions {
		if session.UID == uint32(uid) {
			return true, nil
		}
	}
	var path dbus.ObjectPath
	if err := manager.CallWithContext(ctx, "org.freedesktop.login1.Manager.GetUser", 0, uint32(uid)).Store(&path); err != nil {
		var reply dbus.Error
		if errors.As(err, &reply) && reply.Name == "org.freedesktop.login1.NoSuchUser" {
			return false, nil
		}
		return false, err
	}
	var linger dbus.Variant
	err = bus.Object("org.freedesktop.login1", path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.login1.User", "Linger").Store(&linger)
	if err != nil {
		return false, err
	}
	present, ok := linger.Value().(bool)
	if !ok {
		return false, errors.New("logind returned an invalid Linger property")
	}
	return present, nil
}
