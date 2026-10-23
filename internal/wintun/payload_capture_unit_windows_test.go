//go:build windows

package wintun

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

type captureChunkReader struct {
	body     []byte
	chunk    int
	terminal error
}

func (r *captureChunkReader) Read(p []byte) (int, error) {
	if len(r.body) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(r.body), r.chunk)
	copy(p, r.body[:n])
	r.body = r.body[n:]
	if len(r.body) == 0 {
		return n, r.terminal
	}
	return n, nil
}

func TestPerformancePayloadCapture(t *testing.T) {
	expected := make([]byte, 100003)
	for i := range expected {
		expected[i] = byte(i*13 + i/251)
	}
	for _, offset := range []int{-1, 0, 32767, 32768, 65497, len(expected) - 1} {
		actual := bytes.Clone(expected)
		if offset >= 0 {
			actual[offset] ^= 0x80
			actual[len(actual)-1] ^= 1
		}
		source := &captureChunkReader{body: actual, chunk: 32768, terminal: io.EOF}
		r := &payloadCaptureReader{reader: source, expected: expected}
		h := sha256.New()
		n, err := io.CopyN(h, r, int64(len(expected)))
		want := sha256.Sum256(actual)
		if err != nil || n != int64(len(actual)) || !bytes.Equal(h.Sum(nil), want[:]) {
			t.Fatalf("offset=%d: full SHA/read changed: %d %v", offset, n, err)
		}
		if offset < 0 {
			if r.first != nil {
				t.Fatal("clean payload flagged")
			}
			continue
		}
		d := r.first
		if d == nil || d.Offset != int64(offset) || d.ReadLength > 32768 || len(d.Actual) > 258 || len(d.Actual) != len(d.Expected) {
			t.Fatalf("offset=%d difference=%+v", offset, d)
		}
		end := int(d.ContextOffset) + len(d.Actual)/2
		if d.Expected != hexBytes(expected[d.ContextOffset:end]) || d.Actual != hexBytes(actual[d.ContextOffset:end]) {
			t.Fatal("wrong context")
		}
		// The source read buffer is reused by io.Copy. Evidence must own its bytes.
		clear(actual)
		if d.Expected == d.Actual {
			t.Fatal("lost differing byte")
		}
	}
	boom := errors.New("read failed after bytes")
	r := &payloadCaptureReader{reader: &captureChunkReader{body: []byte{1, 9, 3}, chunk: 3, terminal: boom}, expected: []byte{1, 2, 3}}
	n, err := io.CopyN(io.Discard, r, 4)
	if n != 3 || !errors.Is(err, boom) || r.first.Offset != 1 {
		t.Fatalf("lost partial read/error: %d %v %+v", n, err, r.first)
	}
	if performancePair("TestWintunPerformance/pair11/tcp_8_MBps/inprocess") != 11 || performancePair("TestWintunProfile") != -1 {
		t.Fatal("pair identity")
	}
}
