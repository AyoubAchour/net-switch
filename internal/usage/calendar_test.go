package usage_test

import (
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/usage"
	"testing"
	"time"
	_ "time/tzdata"
)

func TestCalendar(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, now, want string
		cap             *lines.Cap
	}{
		{"spring DST day starts before the skipped hour", "2026-03-29T16:00:00+02:00", "2026-03-29T00:00:00+01:00", &lines.Cap{Period: "day"}},
		{"autumn DST day starts before the repeated hour", "2026-10-25T16:00:00+01:00", "2026-10-25T00:00:00+02:00", &lines.Cap{Period: "day"}},
		{"month rollover follows local midnight", "2026-11-01T00:01:00+01:00", "2026-11-01T00:00:00+01:00", nil},
		{"reset day crosses year boundary", "2027-01-02T08:00:00+01:00", "2026-12-05T00:00:00+01:00", &lines.Cap{Period: "month", ResetDay: 5}},
	} {
		t.Run(c.name, func(t *testing.T) {
			now, _ := time.Parse(time.RFC3339, c.now)
			want, _ := time.Parse(time.RFC3339, c.want)
			got := usage.PeriodStart(c.cap, now.UnixMilli(), location)
			if got != want.UnixMilli() {
				t.Fatalf("got %s want %s", time.UnixMilli(got), want)
			}
		})
	}
}
