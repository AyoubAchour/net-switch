//go:build windows

package wintun

import (
	"encoding/binary"
	"testing"
)

// Preserve the first pilot's fill loop as an explicit profiling reference.
// These CPU-only benchmarks run on hosted runners, never on the routing PC.
func oldPayloadFill(p []byte, transfer uint64, stream int, offset int64) {
	for len(p) > 0 {
		if offset&7 == 0 && len(p) >= 8 {
			binary.LittleEndian.PutUint64(p, payloadWord(transfer, stream, offset))
			p, offset = p[8:], offset+8
			continue
		}
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], payloadWord(transfer, stream, offset))
		n := copy(p, b[offset&7:])
		p, offset = p[n:], offset+int64(n)
	}
}

func BenchmarkPayloadCost(b *testing.B) {
	for _, name := range []string{"old_fill", "fill", "restamp", "old_compare", "compare"} {
		b.Run(name, func(b *testing.B) {
			p := make([]byte, 32<<10)
			fillPayloadWords(p, 96, 5, 0)
			b.SetBytes(int64(len(p)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				switch name {
				case "old_fill":
					oldPayloadFill(p, 96, 5, 0)
				case "fill":
					fillPayloadWords(p, 96, 5, 0)
				case "restamp":
					restampPayloadWords(p, 96+uint64(i), 97+uint64(i))
				case "old_compare":
					v := wordVerifier{transfer: 96, stream: 5}
					v.consumeEvidence(p)
					if v.first != nil {
						b.Fatal("reference mismatch")
					}
				case "compare":
					v := wordVerifier{transfer: 96, stream: 5}
					v.consume(p)
					if v.first != nil {
						b.Fatal("mismatch")
					}
				}
			}
		})
	}
}
