package supervisor

import (
	"io"
	"sync/atomic"
)

// Log never waits on a sink. One bounded sink goroutine may be blocked until
// process exit; its 64 records cannot hold supervision or terminal handling.
type Log struct {
	queue   chan []byte
	Dropped atomic.Uint64
}

func NewLog(sink io.Writer) *Log {
	l := &Log{queue: make(chan []byte, 64)}
	go func() {
		for b := range l.queue {
			if Write(sink, b) != nil {
				return
			}
		}
	}()
	return l
}
func (l *Log) Write(b []byte) (int, error) {
	n := len(b)
	if len(b) > 4096 {
		b = b[:4096]
	}
	copy := append([]byte(nil), b...)
	select {
	case l.queue <- copy:
	default:
		l.Dropped.Add(1)
	}
	return n, nil
}
