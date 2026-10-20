package wire

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestLargeUDPReplyFixture(t *testing.T) {
	seen := map[[32]byte]bool{}
	for _, size := range []int{12000, 65507, 65527} {
		for sequence := range 3 {
			request := UDPReplyRequest("001122aabbcc", size, sequence)
			payload, err := UDPReplyPayload(request)
			repeat, repeatErr := UDPReplyPayload(request)
			if err != nil || repeatErr != nil || len(payload) != size || !bytes.Equal(payload, repeat) {
				t.Fatalf("non-repeatable %d-byte fixture: %v %v", size, err, repeatErr)
			}
			hash := sha256.Sum256(payload)
			if seen[hash] {
				t.Fatal("different requests produced the same payload")
			}
			seen[hash] = true
		}
	}
	for _, request := range []string{
		"T:001122aabbcc:reply:65528:0", "T:001122aabbcc:reply:-1:0", "T:001122aabbcc:reply:12000:-1",
		"T:001122aabbcc:reply:12000:1001", "T:001122aabbzz:reply:12000:0", strings.Repeat("x", 129),
	} {
		if _, err := UDPReplyPayload(request); err == nil {
			t.Fatalf("invalid request accepted: %q", request)
		}
	}
}
