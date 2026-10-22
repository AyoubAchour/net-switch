//go:build windows

package winengine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestReadyTCPPeekDiscardAndLevelRearm(t *testing.T) {
	hosted(t)
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			pool, err := newReadiness()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := pool.close(); err != nil {
					t.Error(err)
				}
			})
			listener, err := net.ListenTCP(network, &net.TCPAddr{IP: loopbackSource(network == "tcp6").AsSlice()})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			c, peer := dialNative(t, pool, listener)
			t.Cleanup(func() {
				if err := c.Close(); err != nil {
					t.Error(err)
				}
			})
			defer peer.Close()
			wakes := make(chan struct{}, 1)
			watch, err := c.Watch(func() {
				select {
				case wakes <- struct{}{}:
				default:
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 256)
			if n, err := c.TryPeek(buf); n != 0 || !errors.Is(err, platform.ErrWouldBlock) {
				t.Fatalf("empty nonblocking peek: %d %v", n, err)
			}
			payload := []byte("peek retains this entire stream until the destination accepts each prefix")
			if _, err := peer.Write(payload); err != nil {
				t.Fatal(err)
			}
			wake := func() {
				t.Helper()
				if err := watch.Arm(true, false); err != nil {
					t.Fatal(err)
				}
				select {
				case <-wakes:
				case <-time.After(time.Second):
					t.Fatal("readable data was not reported on re-arm")
				}
			}
			wake()
			for round := range 3 {
				n, err := c.TryPeek(buf[:1])
				if err != nil || n != 1 || buf[0] != payload[0] {
					t.Fatalf("peek %d changed queued bytes: %q %v", round, buf[:n], err)
				}
				wake() // A second arm must notice the same unread bytes.
			}
			const accepted = 1
			n, err := c.TryDiscard(buf[:accepted])
			if err != nil || n != accepted || !bytes.Equal(buf[:n], payload[:accepted]) {
				t.Fatalf("bounded discard changed its accepted prefix: %q %v", buf[:n], err)
			}
			n, err = c.TryPeek(buf[:1])
			if err != nil || n != 1 || buf[0] != payload[accepted] {
				t.Fatalf("discard consumed unaccepted bytes: %q %v", buf[:n], err)
			}
			// TCP may split or coalesce the remaining stream. Accept every
			// legitimate chunk size while checking the exact peeked prefix.
			for consumed := accepted; consumed < len(payload); {
				wake()
				n, err := c.TryPeek(buf)
				if err != nil || n <= 0 || n > len(payload)-consumed ||
					!bytes.Equal(buf[:n], payload[consumed:consumed+n]) {
					t.Fatalf("remaining peek at %d: n=%d %v", consumed, n, err)
				}
				for discarded := 0; discarded < n; {
					m, err := c.TryDiscard(buf[discarded:n])
					if err != nil || m <= 0 || m > n-discarded ||
						!bytes.Equal(buf[discarded:discarded+m], payload[consumed+discarded:consumed+discarded+m]) {
						t.Fatalf("remaining discard at %d/%d: n=%d %v", consumed, discarded, m, err)
					}
					discarded += m
				}
				consumed += n
			}
			if n, err := c.TryPeek(buf); n != 0 || !errors.Is(err, platform.ErrWouldBlock) {
				t.Fatalf("discard left duplicated data: %d %v", n, err)
			}
			if err := peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			wake()
			if n, err := c.TryPeek(buf); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("peek lost clean EOF: %d %v", n, err)
			}
			watch.Detach()
			t.Log("three exact peeks, level re-arm, one-byte discard, remaining stream and clean EOF passed")
		})
	}
}
