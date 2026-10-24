//go:build windows

package wintun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

const payloadEOFWait = 250 * time.Millisecond

func sendImmutablePayload(w io.Writer, content []byte) (int64, error) {
	return io.Copy(w, bytes.NewReader(content))
}

// EOF is part of the contract. The sender half-closes after its last byte;
// tcpEcho closes after echoing all input. A short bounded completion deadline
// starts at the expected length, with an additional byte cap on hostile output.
func receivePayloadWords(c net.Conn, v *wordVerifier, size int64, onDifference ...func(*wordDifference)) (int64, string, error) {
	b := make([]byte, 32<<10)
	var received int64
	completion := false
	observedMismatch := false
	for {
		p := b
		if remaining := size - received; remaining > 0 && remaining < int64(len(p)) {
			p = p[:remaining]
		}
		n, err := c.Read(p)
		if n > 0 {
			v.consume(b[:n])
			if !observedMismatch && v.first != nil {
				observedMismatch = true
				if len(onDifference) != 0 && onDifference[0] != nil {
					onDifference[0](v.first)
				}
			}
			received += int64(n)
			if !completion && received >= size {
				completion = true
				if e := c.SetReadDeadline(time.Now().Add(payloadEOFWait)); e != nil {
					return received, "completion_error", e
				}
			}
		}
		if err != nil || received >= size+(1<<20) {
			v.finish()
			switch {
			case received < size:
				return received, "under_delivery", fmt.Errorf("%w: under-delivery: received %d/%d: %v", errPayloadIntegrity, received, size, err)
			case received > size:
				return received, "over_delivery", fmt.Errorf("%w: over-delivery: observed %d/%d (EOF=%t)", errPayloadIntegrity, received, size, errors.Is(err, io.EOF))
			case !errors.Is(err, io.EOF):
				return received, "completion_error", fmt.Errorf("expected EOF within %s after %d bytes: %w", payloadEOFWait, received, err)
			case v.first != nil:
				return received, "payload_mismatch", fmt.Errorf("%w: first differing byte %d", errPayloadIntegrity, v.first.Offset)
			default:
				return received, "ok", nil
			}
		}
	}
}

func tcpWordTransfer(t *testing.T, f *fixture, streams int, phase ...string) (float64, error) {
	t.Helper()
	transfer := integrityTransferID.Add(1)
	if err := validPayloadIdentity(transfer, streams); err != nil {
		return 0, err
	}
	label := "transfer"
	if len(phase) > 0 {
		label = phase[0]
	}
	var wg sync.WaitGroup
	var dump sync.Once
	failures := make(chan error, streams)
	contents, release := performancePayloads.prepare(transfer, streams, wordPayloadSize)
	defer release()
	finishResources := startCaptureResources(t, f)
	defer finishResources()
	start := ticks()
	for stream := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.19.240.1")}, Timeout: 5 * time.Second}
			c, err := d.Dial("tcp4", "198.19.240.2:9002")
			if err != nil {
				failures <- err
				return
			}
			defer c.Close()
			if f.wordBoundaries != nil {
				f.wordBoundaries.bind(c.LocalAddr().String(), transfer, stream)
			}
			if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				failures <- err
				return
			}
			type result struct {
				n   int64
				err error
			}
			written := make(chan result, 1)
			go func() {
				// bytes.Reader.WriteTo issues one 64 MiB Write, as the oracle does.
				n, err := sendImmutablePayload(c, contents[stream])
				if err == nil {
					err = c.(*net.TCPConn).CloseWrite()
				}
				written <- result{n, err}
			}()
			v := &wordVerifier{transfer: transfer, stream: stream}
			var onDifference func(*wordDifference)
			if f.wordBoundaries != nil {
				onDifference = func(difference *wordDifference) {
					f.wordBoundaries.hostFailure(c.LocalAddr().String(), difference, "payload_mismatch_detected")
				}
			}
			received, verdict, err := receivePayloadWords(c, v, wordPayloadSize, onDifference)
			if err != nil {
				emit := f.wordBoundaries == nil || f.wordBoundaries.hostFailure(c.LocalAddr().String(), v.first, verdict)
				if emit {
					s, _ := f.io.(*Session)
					record := "tcp_transfer_completion"
					if v.first != nil {
						record = "tcp_payload_difference"
					}
					report(t, map[string]any{"test": record, "verdict": integrityVerdict(err), "failure_kind": verdict, "mode": f.mode, "pair": performancePair(t.Name()), "test_path": t.Name(), "phase": label, "transfer_id": transfer, "stream_id": stream, "local": c.LocalAddr().String(), "length": received, "expected_length": wordPayloadSize, "difference": v.first, "error": err.Error(), "payload_format": "word-v1"})
					report(t, map[string]any{"test": "tcp_failure_before_teardown", "mode": f.mode, "stage": verdict, "local": c.LocalAddr().String(), "received_bytes": received, "expected_bytes": wordPayloadSize, "state": observeSession(s), "fault": fmt.Sprint(f.fault()), "error": err.Error()})
					dump.Do(func() { b := make([]byte, 1<<20); t.Logf("TCP failure goroutines:\n%s", b[:runtime.Stack(b, true)]) })
				}
				c.Close() // Release a blocked sender only after preserving live evidence.
			}
			sent := <-written
			if sent.n != wordPayloadSize || sent.err != nil {
				err = errors.Join(err, fmt.Errorf("sender wrote %d/%d: %v", sent.n, wordPayloadSize, sent.err))
			}
			if err != nil {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(failures)
	var failure error
	for err := range failures {
		failure = errors.Join(failure, err)
	}
	if f.wordBoundaries != nil {
		failure = errors.Join(failure, f.wordBoundaries.complete(transfer, streams))
	}
	if failure != nil {
		return 0, failure
	}
	return float64(wordPayloadSize*streams) / elapsed(start).Seconds() / 1e6, nil
}
