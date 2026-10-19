package tcp

import (
	"context"
	"io"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type counterWriter struct {
	w   io.Writer
	add func(uint64)
}

func (w counterWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.add(uint64(n))
	return n, err
}

// A clean EOF shuts down only that direction. The other side may still have
// its entire response to send. Errors and cancellation close both directions.
func Splice(ctx context.Context, app, remote platform.TCPConn, count func(uint64, uint64), abort func()) error {
	closeBoth := func() { abort(); app.Close(); remote.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan error, 2)
	copyOne := func(dst, src platform.TCPConn, add func(uint64)) {
		_, err := io.CopyBuffer(counterWriter{dst, add}, src, make([]byte, RelayBuffer))
		if err == nil {
			err = dst.CloseWrite()
		}
		src.CloseRead()
		done <- err
	}
	go copyOne(remote, app, func(n uint64) { count(n, 0) })
	go copyOne(app, remote, func(n uint64) { count(0, n) })
	err := <-done
	if err != nil {
		closeBoth()
	}
	other := <-done
	if err == nil {
		err = other
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
