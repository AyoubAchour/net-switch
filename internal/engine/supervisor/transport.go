// Package supervisor contains the bounded transport between a service host and
// its single native child. It owns no policy, lease or forwarding state.
package supervisor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

const Connections = 4

// Line keeps the native newline framing and its existing size limit. No M2
// impersonation primer, JSON rewriting, lease renewal or operation retry occurs.
func Line(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > limit {
			return nil, errors.New("supervisor frame exceeds bound")
		}
		if len(line)+len(part) > cap(line) {
			next := make([]byte, len(line), min(limit, max(4096, max(cap(line)*2, len(line)+len(part)))))
			copy(next, line)
			line = next
		}
		line = append(line, part...)
		if err == nil {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}

// Relay isolates a slow peer to its connection. Each direction holds at most
// two queued frames plus one reader and one writer frame. Four connections
// therefore reserve at most 32 MiB, independent of traffic and client count.
// Queue saturation closes the connection; it never drops an accounting reply
// or blocks the private supervisor channel. Control retries its fenced opId.
func Relay(parent context.Context, public, child io.ReadWriteCloser) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	closeBoth := context.AfterFunc(ctx, func() { public.Close(); child.Close() })
	defer closeBoth()
	var workers sync.WaitGroup
	for _, ends := range [][2]io.ReadWriteCloser{{public, child}, {child, public}} {
		queue := make(chan []byte, 2)
		workers.Go(func() {
			defer close(queue)
			r := bufio.NewReaderSize(ends[0], 4096)
			for {
				line, err := Line(r, protocol.MessageLimit)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						cancel()
					}
					return
				}
				select {
				case queue <- line:
					continue
				default:
				}
				deadline := time.NewTimer(time.Second)
				select {
				case queue <- line:
					deadline.Stop()
				case <-ctx.Done():
					deadline.Stop()
					return
				case <-deadline.C:
					cancel()
					return
				}
			}
		})
		workers.Go(func() {
			defer cancel()
			for {
				select {
				case line, ok := <-queue:
					if !ok {
						return
					}
					if err := Write(ends[1], line); err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		})
	}
	workers.Wait()
}

func Write(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
