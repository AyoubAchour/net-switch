package usage

import (
	"testing"
	"time"
)

func TestWindowsZoneMappings(t *testing.T) {
	for key, name := range windowsZones {
		if _, err := time.LoadLocation(name); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
	}
	for _, c := range []struct{ key, want string }{{"Pacific SA Standard Time", "America/Santiago"}, {"Cuba Standard Time", "America/Havana"}, {"Egypt Standard Time", "Africa/Cairo"}} {
		if windowsZones[c.key] != c.want {
			t.Fatal(c)
		}
	}
	t.Setenv("TZ", "America/Santiago")
	loc, err := LocalLocation()
	if err != nil || loc.String() != "America/Santiago" {
		t.Fatalf("%v %v", loc, err)
	}
	t.Setenv("TZ", "")
	loc, err = LocalLocation()
	if err != nil || loc == time.Local {
		t.Fatalf("system IANA lookup: %v %v", loc, err)
	}
}
