package usage_test

import (
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/usage"
	"testing"
	"time"
)

func TestMidnightDisambiguation(t *testing.T) {
	for _, c := range []struct{ zone, now, want string }{
		{"America/Santiago", "2026-09-06T12:00:00Z", "2026-09-06T04:00:00Z"},
		{"America/Havana", "2026-03-08T12:00:00Z", "2026-03-08T05:00:00Z"},
		{"Africa/Cairo", "2026-04-24T12:00:00Z", "2026-04-23T22:00:00Z"},
		{"America/Havana", "2026-11-01T12:00:00Z", "2026-11-01T04:00:00Z"},
	} {
		t.Run(c.zone+"/"+c.now, func(t *testing.T) {
			loc, err := time.LoadLocation(c.zone)
			if err != nil {
				t.Fatal(err)
			}
			now, _ := time.Parse(time.RFC3339, c.now)
			want, _ := time.Parse(time.RFC3339, c.want)
			for _, cap := range []*lines.Cap{{Period: "day"}, {Period: "month", ResetDay: now.In(loc).Day()}} {
				got := usage.PeriodStart(cap, now.UnixMilli(), loc)
				if got != want.UnixMilli() {
					t.Fatalf("got %s; want %s", time.UnixMilli(got).UTC(), want)
				}
			}
		})
	}
}
