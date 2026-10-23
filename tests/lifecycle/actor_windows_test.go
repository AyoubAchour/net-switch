package lifecycle_test

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativeActorAccountChecks(t *testing.T) {
	for _, tc := range []struct {
		kind            uint32
		elevated, allow bool
	}{{1, false, true}, {1, true, false}, {2, true, false}, {3, false, false}, {0, false, false}} {
		if err := checkActorToken(tc.kind, tc.elevated); (err == nil) != tc.allow {
			t.Fatal("split/elevated token classification", tc, err)
		}
	}
	ptr := func(s string) *uint16 {
		t.Helper()
		p, err := windows.UTF16PtrFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, name := range []string{"NSNativeOther", "NSLifecycleOwner", "NSLifecycleOther"} {
		t.Run(name, func(t *testing.T) {
			valid := actorUserInfo{Name: ptr(name), Comment: ptr(actorComment), Privilege: 1, Flags: 0x10201}
			if err := checkWindowsActorInfo(name, &valid); err != nil {
				t.Fatal("normal account with optional home/script unset", err)
			}
			// Hosted NetUserGetInfo returns 0 for our newly created normal
			// account, despite NetUserAdd requiring USER_PRIV_USER (1) as input.
			observed := valid
			observed.Privilege = 0
			if err := checkWindowsActorInfo(name, &observed); err != nil {
				t.Fatal("hosted normal-account observation rejected", err)
			}
			for _, tc := range []struct {
				name   string
				change func(*actorUserInfo)
			}{
				{"administrator", func(u *actorUserInfo) { u.Privilege = 2 }},
				{"unknown-privilege", func(u *actorUserInfo) { u.Privilege = 99 }},
				{"foreign-name", func(u *actorUserInfo) { u.Name = ptr("unrelated") }},
				{"foreign-comment", func(u *actorUserInfo) { u.Comment = ptr("unrelated") }},
				{"disabled", func(u *actorUserInfo) { u.Flags |= 2 }},
				{"machine-account", func(u *actorUserInfo) { u.Flags = 0x11001 }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					u := valid
					tc.change(&u)
					err := checkWindowsActorInfo(name, &u)
					if err == nil || !strings.Contains(err.Error(), "privilege=") || !strings.Contains(err.Error(), "flags=") || !strings.Contains(err.Error(), "comment=") {
						t.Fatal("unexpected account accepted or observed properties omitted", err)
					}
				})
			}
		})
	}
	if err := checkWindowsActorGroup("NSNativeOther", "localized Users", "S-1-5-32-545"); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"S-1-5-32-544", "S-1-5-32-551", "S-1-5-32-546", "unexpected"} {
		if err := checkWindowsActorGroup("NSNativeOther", "Users", sid); err == nil || !strings.Contains(err.Error(), sid) {
			t.Fatal("non-Users membership accepted or observed SID omitted", sid, err)
		}
	}
}
