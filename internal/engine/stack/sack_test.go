package stack

import (
	"slices"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Every tree owns its sequence ranges even when its recycled nodes come from
// another connection. Exercise removal, reuse and reset concurrently.
func TestSACKNodeReuseKeepsConnectionRangesSeparate(t *testing.T) {
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Go(func() {
			base := seqnum.Value(100000 * worker)
			s := tcp.NewSACKScoreboard(100, base)
			for round := range 100 {
				var want []header.SACKBlock
				for i := range 64 {
					start := base + seqnum.Value(i*200+round*20000)
					r := header.SACKBlock{Start: start, End: start + 100}
					s.Insert(r)
					want = append(want, r)
				}
				if got, _ := s.Copy(); !slices.Equal(got, want) || s.Sacked() != 6400 {
					t.Errorf("connection %d round %d: got %v (%d bytes), want %v", worker, round, got, s.Sacked(), want)
					return
				}
				s.Delete(want[31].End)
				if got, _ := s.Copy(); !slices.Equal(got, want[32:]) || s.Sacked() != 3200 {
					t.Errorf("connection %d: delete crossed ranges: %v", worker, got)
					return
				}
				s.Delete(want[63].End)
				s.Reset()
				if !s.Empty() || s.Sacked() != 0 {
					t.Errorf("connection %d: reset retained ranges", worker)
					return
				}
			}
		})
	}
	workers.Wait()
}
