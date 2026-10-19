package tcp

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type halfConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

var relayBuffers = sync.Pool{New: func() any { b := make([]byte, RelayBuffer); return &b }}

// A clean EOF shuts down only that direction. The other side may still have
// its entire response to send. Errors and cancellation close both directions.
func Splice(ctx context.Context, app halfConn, remote platform.TCPConn, count func(uint64, uint64), abort func()) error {
	closeBoth := sync.OnceFunc(func() { remote.SetLinger(0); abort(); app.Close(); remote.Close() })
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan error, 2)
	copyOne := func(dst, src halfConn, add func(uint64)) {
		var err error
		for {
			// An idle read must not retain a 32 KiB pool buffer. At the flow
			// limit, two blocked reads per flow would retain 4 GiB and make
			// the 512 MiB GC target spend all its time scanning live objects.
			if ready, ok := src.(interface{ WaitReadable(context.Context) error }); ok {
				if err = ready.WaitReadable(ctx); err != nil {
					break
				}
			}
			b := relayBuffers.Get().(*[]byte)
			n, readErr := src.Read(*b)
			if n > 0 {
				written, writeErr := dst.Write((*b)[:n])
				add(uint64(written))
				err = writeErr
				if err == nil && written != n {
					err = io.ErrShortWrite
				}
			}
			relayBuffers.Put(b)
			if err != nil {
				break
			}
			if readErr != nil {
				if readErr != io.EOF {
					err = readErr
				}
				break
			}
		}
		if err == nil {
			err = dst.CloseWrite()
		}
		src.CloseRead()
		if err != nil {
			closeBoth()
		}
		done <- err
	}
	go copyOne(remote, app, func(n uint64) { count(n, 0) })
	// Reuse the caller for one direction. A third idle goroutine per flow
	// only waits on done and adds another stack to every GC root scan.
	copyOne(app, remote, func(n uint64) { count(0, n) })
	err := <-done
	if err != nil {
		closeBoth()
	}
	other := <-done
	if err == nil {
		err = other
	}
	if err != nil {
		closeBoth()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
