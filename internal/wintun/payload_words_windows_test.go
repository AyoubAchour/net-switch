//go:build windows

package wintun

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sync"
)

const wordPayloadSize = 64 << 20

// The wire format is a bijection over (32-bit transfer, 8-bit stream,
// 24-bit word index). Never silently wrap an identity.
// Multiplication spreads adjacent indices across the word; its odd multiplier
// has the inverse below in arithmetic modulo 2^64. This is not authentication.
func payloadWord(transfer uint64, stream int, offset int64) uint64 {
	x := transfer<<32 | uint64(stream)<<24 | uint64(offset/8)
	return bits.RotateLeft64(x*0xbf58476d1ce4e5b9, 23)
}

type decodedPayloadWord struct {
	Transfer uint64 `json:"transfer_id"`
	Stream   int    `json:"stream_id"`
	Offset   int64  `json:"offset"`
}

func decodePayloadWord(w uint64) decodedPayloadWord {
	x := bits.RotateLeft64(w, -23) * 0x96de1b173f119089
	return decodedPayloadWord{x >> 32, int(x >> 24 & 255), int64(x&0xffffff) * 8}
}

func fillPayloadWords(p []byte, transfer uint64, stream int, offset int64) {
	if offset&7 != 0 && len(p) > 0 {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], payloadWord(transfer, stream, offset))
		n := copy(p, b[offset&7:])
		p, offset = p[n:], offset+int64(n)
	}
	base := transfer<<32 | uint64(stream)<<24 | uint64(offset/8)
	for len(p) >= 8 {
		binary.LittleEndian.PutUint64(p, bits.RotateLeft64(base*0xbf58476d1ce4e5b9, 23))
		base++
		p = p[8:]
	}
	if len(p) > 0 {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], bits.RotateLeft64(base*0xbf58476d1ce4e5b9, 23))
		copy(p, b[:])
	}
}

// Change only the transfer field in the reversible encoding. Addition is
// modulo 2^64; stream and word-index bits are preserved without allocation.
func restampPayloadWords(p []byte, oldTransfer, transfer uint64) {
	delta := ((transfer - oldTransfer) << 32) * 0xbf58476d1ce4e5b9
	for len(p) >= 8 {
		word := bits.RotateLeft64(binary.LittleEndian.Uint64(p), -23)
		binary.LittleEndian.PutUint64(p, bits.RotateLeft64(word+delta, 23))
		p = p[8:]
	}
}

type payloadBank struct {
	mu       sync.Mutex
	data     [8][]byte
	transfer [8]uint64
}

// One bank per process, leased until every sender has completed. Preparation
// is outside timing; no later transfer can restamp a socket's borrowed bytes.
var performancePayloads payloadBank

func (b *payloadBank) prepare(transfer uint64, streams, size int) ([][]byte, func()) {
	b.mu.Lock()
	for stream := range b.data {
		if b.data[stream] == nil {
			b.data[stream] = make([]byte, size)
			fillPayloadWords(b.data[stream], 0, stream, 0)
		}
	}
	for stream := range streams {
		restampPayloadWords(b.data[stream], b.transfer[stream], transfer)
		b.transfer[stream] = transfer
	}
	return b.data[:streams], b.mu.Unlock
}

type wordDifference struct {
	Offset          int64               `json:"first_differing_offset"`
	Expected        decodedPayloadWord  `json:"expected_word"`
	Actual          *decodedPayloadWord `json:"actual_word,omitempty"`
	ExpectedHex     string              `json:"expected_word_hex"`
	ActualHex       string              `json:"actual_word_hex"`
	ContextHex      string              `json:"actual_context_hex,omitempty"`
	ContextOffset   int64               `json:"context_offset"`
	Source          *decodedPayloadWord `json:"confirmed_source,omitempty"`
	SourceAt        int64               `json:"source_observed_at,omitempty"`
	Shift           *int64              `json:"source_offset_minus_received_offset,omitempty"`
	RunLength       int64               `json:"bad_run_length"`
	Realigned       bool                `json:"realigned"`
	ObservedThrough int64               `json:"observed_through"`
}

// One verifier belongs to one stream. Partial words survive arbitrary socket
// read boundaries. A bad run ends at sixteen consecutive correct bytes, not an
// accidental matching byte inside a scrambled word. Run length is measured
// from the first differing byte to the start of that matching byte run.
type wordVerifier struct {
	transfer   uint64
	stream     int
	offset     int64
	pending    [8]byte
	used       int
	first      *wordDifference
	matching   int
	evidence   [32]byte
	evidenceN  int
	evidenceAt int64
}

func (v *wordVerifier) consume(p []byte) {
	if v.first != nil {
		v.consumeEvidence(p)
		return
	}
	if v.used != 0 {
		n := min(len(p), 8-v.used)
		v.consumeEvidence(p[:n])
		p = p[n:]
		if v.used != 0 || v.first != nil {
			v.consumeEvidence(p)
			return
		}
	}
	base := v.transfer<<32 | uint64(v.stream)<<24 | uint64(v.offset/8)
	end := len(p) &^ 7
	for i := 0; i < end; i += 8 {
		if binary.LittleEndian.Uint64(p[i:]) != bits.RotateLeft64(base*0xbf58476d1ce4e5b9, 23) {
			v.offset += int64(i)
			v.consumeEvidence(p[i:])
			return
		}
		base++
	}
	v.offset += int64(end)
	v.used = copy(v.pending[:], p[end:])
}

// Original loop retained for split words/failure evidence and profiling the
// pre-optimization comparison cost. Clean aligned chunks never enter it.
func (v *wordVerifier) consumeEvidence(p []byte) {
	for len(p) > 0 {
		// Clean words are compared directly in the socket buffer.
		if v.used == 0 && len(p) >= 8 && (v.first == nil || v.first.Realigned) && binary.LittleEndian.Uint64(p) == payloadWord(v.transfer, v.stream, v.offset) {
			p, v.offset = p[8:], v.offset+8
			continue
		}
		n := copy(v.pending[v.used:], p)
		v.used += n
		p = p[n:]
		if v.used < 8 {
			continue
		}
		actual := binary.LittleEndian.Uint64(v.pending[:])
		expected := payloadWord(v.transfer, v.stream, v.offset)
		if actual != expected && v.first == nil {
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], expected)
			i := 0
			for b[i] == v.pending[i] {
				i++
			}
			decoded := decodePayloadWord(actual)
			v.first = &wordDifference{Offset: v.offset + int64(i), Expected: decodePayloadWord(expected), Actual: &decoded, ExpectedHex: hexBytes(b[:]), ActualHex: hexBytes(v.pending[:])}
			v.evidenceAt = v.offset
		}
		if d := v.first; d != nil && !d.Realigned {
			if v.evidenceN < len(v.evidence) {
				v.evidenceN += copy(v.evidence[v.evidenceN:], v.pending[:])
				d.ContextHex, d.ContextOffset = hexBytes(v.evidence[:v.evidenceN]), v.evidenceAt
				v.decodeSource()
			}
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], expected)
			d.ObservedThrough = v.offset + 8
			d.RunLength = d.ObservedThrough - d.Offset
			for i := range b {
				if v.offset+int64(i) < d.Offset {
					continue
				}
				if b[i] == v.pending[i] {
					v.matching++
				} else {
					v.matching = 0
				}
				if v.matching == 16 {
					d.Realigned = true
					d.RunLength = v.offset + int64(i) + 1 - 16 - d.Offset
					if d.Source != nil && d.SourceAt+24 > d.Offset+d.RunLength {
						d.Source, d.Shift = nil, nil
						d.SourceAt = 0
					}
					break
				}
			}
		}
		v.offset += 8
		v.used = 0
	}
}

// A decoded arbitrary integer is not evidence of origin. Require three
// consecutive source words, including when a byte shift breaks alignment.
func (v *wordVerifier) decodeSource() {
	if v.first.Source != nil {
		return
	}
	for i := 0; i+24 <= v.evidenceN; i++ {
		a := decodePayloadWord(binary.LittleEndian.Uint64(v.evidence[i:]))
		if a.Transfer == 0 || a.Transfer > v.transfer || a.Stream >= 8 || a.Offset+24 > wordPayloadSize {
			continue
		}
		b := decodePayloadWord(binary.LittleEndian.Uint64(v.evidence[i+8:]))
		c := decodePayloadWord(binary.LittleEndian.Uint64(v.evidence[i+16:]))
		if b.Transfer != a.Transfer || c.Transfer != a.Transfer || b.Stream != a.Stream || c.Stream != a.Stream || b.Offset != a.Offset+8 || c.Offset != a.Offset+16 {
			continue
		}
		at := v.evidenceAt + int64(i)
		if a.Transfer == v.transfer && a.Stream == v.stream && a.Offset == at {
			continue
		}
		shift := a.Offset - at
		v.first.Source, v.first.SourceAt, v.first.Shift = &a, at, &shift
		return
	}
}

func (v *wordVerifier) finish() {
	if v.used == 0 {
		return
	}
	var expected [8]byte
	binary.LittleEndian.PutUint64(expected[:], payloadWord(v.transfer, v.stream, v.offset))
	if v.first == nil {
		for i := 0; i < v.used; i++ {
			if expected[i] != v.pending[i] {
				v.first = &wordDifference{Offset: v.offset + int64(i), Expected: decodePayloadWord(binary.LittleEndian.Uint64(expected[:])), ExpectedHex: hexBytes(expected[:v.used]), ActualHex: hexBytes(v.pending[:v.used])}
				break
			}
		}
	}
	if v.first != nil && !v.first.Realigned {
		v.first.ObservedThrough = v.offset + int64(v.used)
		v.first.RunLength = v.first.ObservedThrough - v.first.Offset
		for i := 0; i < v.used; i++ {
			if v.offset+int64(i) < v.first.Offset {
				continue
			}
			if expected[i] == v.pending[i] {
				v.matching++
			} else {
				v.matching = 0
			}
			if v.matching == 16 {
				v.first.Realigned = true
				v.first.RunLength = v.offset + int64(i) + 1 - 16 - v.first.Offset
				if v.first.Source != nil && v.first.SourceAt+24 > v.first.Offset+v.first.RunLength {
					v.first.Source, v.first.Shift = nil, nil
					v.first.SourceAt = 0
				}
				break
			}
		}
	}
}

func validPayloadIdentity(transfer uint64, streams int) error {
	if transfer == 0 || transfer > 0xffffffff || streams < 1 || streams > 8 {
		return fmt.Errorf("payload identity out of range: transfer=%d streams=%d", transfer, streams)
	}
	return nil
}
