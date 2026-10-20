//go:build linux

package linux

import (
	"errors"
	"io"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

// A single kernel readiness loop serves all real TCP sockets. Monotonic
// registration IDs, not fd numbers or Go pointers, make queued stale events
// harmless after Detach and descriptor reuse. Callbacks only schedule work.
type socketPoller struct {
	mu      sync.Mutex
	fd      int
	next    uint64
	entries map[uint64]*socketWatch
}
type socketWatch struct {
	p          *socketPoller
	s          *tcpSocket
	id         uint64
	wake       func()
	attached   bool // protected by p.mu
	registered bool
}

var tcpPoller = sync.OnceValues(func() (*socketPoller, error) {
	fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	p := &socketPoller{fd: fd, entries: make(map[uint64]*socketWatch)}
	go p.run()
	return p, nil
})

func (p *socketPoller) run() {
	var events [256]unix.EpollEvent
	for {
		n, err := unix.EpollWait(p.fd, events[:], -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			panic("TCP readiness poller: " + err.Error())
		}
		for _, event := range events[:n] {
			id := uint64(uint32(event.Fd)) | uint64(uint32(event.Pad))<<32
			p.mu.Lock()
			w := p.entries[id]
			p.mu.Unlock()
			if w != nil {
				w.wake()
			}
		}
	}
}

func (s *tcpSocket) Watch(wake func()) (platform.Readiness, error) {
	p, err := tcpPoller()
	if err != nil {
		return nil, err
	}
	if err := s.takeReadiness(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	w := &socketWatch{p: p, s: s, id: p.next, wake: wake}
	w.attached = true
	p.entries[w.id] = w
	return w, nil
}

func (w *socketWatch) Arm(read, write bool) error {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	if !w.attached {
		return nil
	}
	mask := uint32(unix.EPOLLONESHOT)
	if read {
		mask |= unix.EPOLLIN | unix.EPOLLRDHUP
	}
	if write {
		mask |= unix.EPOLLOUT
	}
	var armErr error
	err := w.s.control(func(fd uintptr) {
		if !read && !write {
			// EPOLLHUP is unconditional, even with an empty mask. Delete the
			// interest while app-side backpressure prevents consuming EOF.
			if w.registered {
				armErr = unix.EpollCtl(w.p.fd, unix.EPOLL_CTL_DEL, int(fd), nil)
				w.registered = false
			}
			return
		}
		op := unix.EPOLL_CTL_ADD
		if w.registered {
			op = unix.EPOLL_CTL_MOD
		}
		armErr = unix.EpollCtl(w.p.fd, op, int(fd), &unix.EpollEvent{Events: mask, Fd: int32(w.id), Pad: int32(w.id >> 32)})
		if armErr == nil {
			w.registered = true
		}
	})
	return errors.Join(err, armErr)
}

func (w *socketWatch) Detach() {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	if !w.attached {
		return
	}
	w.attached = false
	delete(w.p.entries, w.id)
	if w.registered {
		_ = w.s.control(func(fd uintptr) { _ = unix.EpollCtl(w.p.fd, unix.EPOLL_CTL_DEL, int(fd), nil) })
	}
}

func (s *tcpSocket) TryRead(b []byte) (int, error) {
	var n int
	var readErr error
	err := s.control(func(fd uintptr) {
		for {
			n, readErr = unix.Read(int(fd), b)
			if readErr != unix.EINTR {
				break
			}
		}
	})
	if readErr == unix.EAGAIN {
		readErr = platform.ErrWouldBlock
	}
	if err == nil && readErr == nil && n == 0 {
		readErr = io.EOF
	}
	if err != nil {
		return max(n, 0), err
	}
	return max(n, 0), readErr
}

func (s *tcpSocket) TryWrite(b []byte) (int, error) {
	var n int
	var writeErr error
	err := s.control(func(fd uintptr) {
		for {
			n, writeErr = unix.Write(int(fd), b)
			if writeErr != unix.EINTR {
				break
			}
		}
	})
	if writeErr == unix.EAGAIN {
		writeErr = platform.ErrWouldBlock
	}
	if err != nil {
		return max(n, 0), err
	}
	return max(n, 0), writeErr
}
