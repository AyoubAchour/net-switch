package flows

import "testing"

func TestIncompleteReconnectCannotWidenAnotherSelector(t *testing.T) {
	for _, s := range []Selector{
		{Line: "B", App: "unrelated"},
		{IDs: []uint64{1}, NotLine: "A"},
		{IPv6: true, App: "unrelated"},
	} {
		if err := s.Validate(); err == nil {
			t.Fatalf("accepted incomplete reconnect selector %+v", s)
		}
	}
}
