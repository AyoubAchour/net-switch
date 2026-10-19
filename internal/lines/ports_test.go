package lines_test

import (
	"github.com/AyoubAchour/net-switch/internal/lines"
	"math"
	"testing"
)

func TestPorts(t *testing.T) {
	t.Run("every port goes to exactly one line, and each line gets its share of them", func(t *testing.T) {
		shares := []lines.Share{{ID: "a1", Value: 0.5}, {ID: "b2", Value: 0.3}, {ID: "c3", Value: 0.2}}
		ports := lines.AssignPorts(shares)
		seen := map[int]bool{}
		for _, share := range shares {
			for _, p := range ports[share.ID] {
				if seen[p] || p < 1024 || p > 65535 {
					t.Fatal(p)
				}
				seen[p] = true
			}
			if math.Abs(float64(len(ports[share.ID]))/64512-share.Value) >= 0.001 {
				t.Fatal(share)
			}
		}
		if len(seen) != 64512 {
			t.Fatal(len(seen))
		}
	})
	t.Run("any eight connections 1, 2 or 4 ports apart split close to the shares", func(t *testing.T) {
		for _, c := range []struct {
			share float64
			worst float64
		}{{0.5, 1}, {0.75, 2}} {
			shares := []lines.Share{{ID: "a1", Value: c.share}, {ID: "b2", Value: 1 - c.share}}
			for _, step := range []int{1, 2, 4} {
				for start := 1024; start+7*step <= 65535; start++ {
					count := 0
					for i := 0; i < 8; i++ {
						if lines.LineForPort(float64(start+i*step), shares) == "a1" {
							count++
						}
					}
					if math.Abs(float64(count)-c.share*8) > c.worst {
						t.Fatalf("start %d step %d count %d", start, step, count)
					}
				}
			}
		}
	})
	t.Run("the ports Windows handed out on this PC split four and four", func(t *testing.T) {
		shares := []lines.Share{{ID: "a1", Value: 0.5}, {ID: "b2", Value: 0.5}}
		for _, ports := range [][]int{{64393, 64395, 64397, 64399, 64401, 64403, 64405, 64407}, {49673, 49674, 49675, 49676, 49677, 49678, 49680, 49681}} {
			count := 0
			for _, p := range ports {
				if lines.LineForPort(float64(p), shares) == "a1" {
					count++
				}
			}
			if math.Abs(float64(count)-4) > 1 {
				t.Fatal(count)
			}
		}
	})
}
