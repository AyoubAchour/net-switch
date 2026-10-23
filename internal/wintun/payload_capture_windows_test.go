//go:build windows

package wintun

import (
	"bytes"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
)

// Capture owns only the first differing read's small excerpt. The successful
// path compares against the existing shared sender slice, never retains a body,
// generates a pattern, or does an extra hash. io.CopyN still hashes every read.
type payloadCaptureReader struct {
	reader   io.Reader
	expected []byte
	offset   int64
	first    *payloadDifference
}

type payloadDifference struct {
	Offset        int64  `json:"first_differing_offset"`
	ReadOffset    int64  `json:"read_offset"`
	ReadLength    int    `json:"read_length"`
	ContextOffset int64  `json:"context_offset"`
	Expected      string `json:"expected_hex"`
	Actual        string `json:"actual_hex"`
}

func (r *payloadCaptureReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.first == nil {
		expected := r.expected[r.offset : r.offset+int64(n)]
		if !bytes.Equal(p[:n], expected) {
			i := 0
			for p[i] == expected[i] {
				i++
			}
			start, end := max(0, i-64), min(n, i+65)
			r.first = &payloadDifference{Offset: r.offset + int64(i), ReadOffset: r.offset, ReadLength: n,
				ContextOffset: r.offset + int64(start), Expected: hexBytes(expected[start:end]), Actual: hexBytes(p[start:end])}
		}
	}
	r.offset += int64(n)
	return n, err
}

func hexBytes(p []byte) string {
	return hex.EncodeToString(p)
}

func performancePair(name string) int {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, "pair") {
			if n, err := strconv.Atoi(strings.TrimPrefix(part, "pair")); err == nil {
				return n
			}
		}
	}
	return -1 // Profiles have no pair; never invent one.
}
