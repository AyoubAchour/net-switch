//go:build windows

package wintun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestPayloadWordsIdentityAndChunking(t *testing.T) {
	for _, transfer := range []uint64{1, 96, 0xffffffff} {
		for _, stream := range []int{0, 4, 7} {
			for _, off := range []int64{0, 8, 25452288, wordPayloadSize - 8} {
				got := decodePayloadWord(payloadWord(transfer, stream, off))
				if got != (decodedPayloadWord{transfer, stream, off}) {
					t.Fatalf("round trip: %+v", got)
				}
			}
		}
	}
	if validPayloadIdentity(1<<32, 8) == nil || validPayloadIdentity(1, 9) == nil {
		t.Fatal("identity wrapped")
	}
	var sent bytes.Buffer
	n, err := sendPayloadWords(&sent, 96, 5, 300003)
	if n != 300003 || err != nil {
		t.Fatal(n, err)
	}
	for _, chunk := range []int{1, 3, 7, 8, 9, 32767, 32768} {
		v := wordVerifier{transfer: 96, stream: 5}
		p := sent.Bytes()
		for len(p) > 0 {
			n := min(chunk, len(p))
			v.consume(p[:n])
			p = p[n:]
		}
		v.finish()
		if v.first != nil {
			t.Fatalf("chunk %d: %+v", chunk, v.first)
		}
	}
}

func TestPayloadWordsSubstitutionAndRealignment(t *testing.T) {
	for _, source := range []decodedPayloadWord{{96, 5, 4096 + 34}, {96, 4, 4096}, {95, 5, 8192}} {
		for _, chunk := range []int{1, 7, 32768} {
			p := make([]byte, 12000)
			fillPayloadWords(p, 96, 5, 0)
			expected := bytes.Clone(p)
			fillPayloadWords(p[4096:8195], source.Transfer, source.Stream, source.Offset)
			end := 8195
			for p[end-1] == expected[end-1] {
				end--
			}
			v := wordVerifier{transfer: 96, stream: 5}
			for len(p) > 0 {
				n := min(chunk, len(p))
				v.consume(p[:n])
				p = p[n:]
			}
			v.finish()
			d := v.first
			if d == nil || !d.Realigned || d.Offset+d.RunLength != int64(end) || d.Source == nil {
				t.Fatalf("source=%+v chunk=%d difference=%+v", source, chunk, d)
			}
			if d.Source.Transfer != source.Transfer || d.Source.Stream != source.Stream || *d.Shift != source.Offset-4096 {
				t.Fatalf("wrong origin: %+v", d)
			}
		}
	}
}

func TestPayloadWordsUnattributedAndTrailingDamage(t *testing.T) {
	for _, offset := range []int{0, 7, 32767, 32768, 40002} {
		p := make([]byte, 40003)
		fillPayloadWords(p, 1, 0, 0)
		p[offset] ^= 1
		v := wordVerifier{transfer: 1, stream: 0}
		v.consume(p)
		v.finish()
		if v.first == nil || v.first.Offset != int64(offset) || v.first.Source != nil {
			t.Fatalf("offset=%d difference=%+v", offset, v.first)
		}
		if offset < 40002 && (!v.first.Realigned || v.first.RunLength != 1) {
			t.Fatalf("single byte run: %+v", v.first)
		}
		if offset == 40002 && (v.first.Realigned || v.first.RunLength != 1) {
			t.Fatalf("unclosed tail: %+v", v.first)
		}
	}
}

type payloadTestConn struct {
	io.Reader
	deadline time.Time
}

func (*payloadTestConn) Write([]byte) (int, error)           { return 0, errors.New("unexpected write") }
func (*payloadTestConn) Close() error                        { return nil }
func (*payloadTestConn) LocalAddr() net.Addr                 { return nil }
func (*payloadTestConn) RemoteAddr() net.Addr                { return nil }
func (c *payloadTestConn) SetDeadline(t time.Time) error     { c.deadline = t; return nil }
func (c *payloadTestConn) SetReadDeadline(t time.Time) error { c.deadline = t; return nil }
func (*payloadTestConn) SetWriteDeadline(time.Time) error    { return nil }

func TestPayloadWordsLengthVerdicts(t *testing.T) {
	for _, size := range []int{4095, 4096, 4097} {
		p := make([]byte, size)
		fillPayloadWords(p, 1, 0, 0)
		c := &payloadTestConn{Reader: &captureChunkReader{body: p, chunk: 7, terminal: io.EOF}}
		v := &wordVerifier{transfer: 1, stream: 0}
		n, verdict, err := receivePayloadWords(c, v, 4096)
		want := "ok"
		if size < 4096 {
			want = "under_delivery"
		}
		if size > 4096 {
			want = "over_delivery"
		}
		if n != int64(size) || verdict != want || (err == nil) != (want == "ok") {
			t.Fatal(n, verdict, err)
		}
	}
}

func TestPayloadWordsDelayedExtraAndMissingEOF(t *testing.T) {
	for _, extra := range []bool{false, true} {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		done := make(chan struct{})
		go func() {
			defer close(done)
			p := make([]byte, 4096)
			fillPayloadWords(p, 1, 0, 0)
			server.Write(p)
			if extra {
				time.Sleep(10 * time.Millisecond)
				server.Write([]byte{9})
				server.Close()
			}
		}()
		v := &wordVerifier{transfer: 1, stream: 0}
		_, verdict, err := receivePayloadWords(client, v, 4096)
		want := "completion_error"
		if extra {
			want = "over_delivery"
		}
		if err == nil || verdict != want {
			t.Fatal(verdict, err)
		}
		client.Close()
		server.Close()
		<-done
	}
}
