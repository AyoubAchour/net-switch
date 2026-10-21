package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

type connection struct {
	events          chan Event
	replies         chan Reply
	slots           chan struct{}
	finished        func()
	terminal        chan *terminalDelivery
	done            chan struct{}
	cancel          context.CancelFunc
	stopWork        context.CancelFunc
	terminalStarted chan struct{}
}

// Serve owns the transport until EOF or cancellation. Its reader and writer
// are independent of forwarding; at most 16 replies may be outstanding.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work, stopWork := context.WithCancel(ctx)
	defer stopWork()
	defer rw.Close()
	stop := context.AfterFunc(ctx, func() { rw.Close() })
	defer stop()
	c := &connection{events: make(chan Event, 64), replies: make(chan Reply, Outstanding), slots: make(chan struct{}, Outstanding), finished: s.finished,
		terminal: make(chan *terminalDelivery, 1), done: make(chan struct{}), cancel: cancel, stopWork: stopWork,
		terminalStarted: make(chan struct{})}
	defer close(c.done)
	s.mu.Lock()
	if len(s.clients) >= 4 {
		s.mu.Unlock()
		return errors.New("too many control connections")
	}
	s.clients[c] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.clients, c); s.mu.Unlock() }()
	writer := make(chan error, 1)
	go func() { err := c.write(ctx, rw); writer <- err; cancel() }()
	reader := bufio.NewReaderSize(rw, 4096)
	var workers sync.WaitGroup
	var readErr error
	for {
		reserved := true
		select {
		case c.slots <- struct{}{}:
		default:
			select {
			case c.slots <- struct{}{}:
			case <-c.terminalStarted:
				// No ordinary reply slot is available. Keep reading solely
				// for the final receipt; it requires no reply slot of its own.
				reserved = false
			case <-ctx.Done():
				readErr = ctx.Err()
			}
		}
		if readErr != nil {
			break
		}
		line, err := readLine(reader)
		if err != nil {
			if reserved {
				<-c.slots
			}
			readErr = err
			break
		}
		r, err := Decode(line)
		if !reserved {
			if err == nil && r.Method == "terminalAck" {
				s.handle(work, r, c)
			}
			continue
		}
		if err != nil {
			select {
			case c.replies <- Reply{ID: r.ID, Error: err.Error()}:
			case <-ctx.Done():
				<-c.slots
			}
			continue
		}
		workers.Go(func() {
			reply := s.handle(work, r, c)
			select {
			case c.replies <- reply:
			case <-ctx.Done():
				<-c.slots
			}
		})
	}
	cancel()
	workers.Wait()
	writeErr := <-writer
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	return writeErr
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > MessageLimit {
			return nil, errors.New("message exceeds 1 MiB")
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

func (c *connection) write(ctx context.Context, w io.Writer) error {
	var pending *Event
	for {
		var value any
		reply := false
		var terminal *terminalDelivery
		// A terminal record has a reserved slot, independent of droppable logs.
		select {
		case terminal = <-c.terminal:
			value = terminal.message
		default:
		}
		// Always recheck replies before writing a selected log/event.
		if value == nil {
			select {
			case r := <-c.replies:
				value = r
				reply = true
			default:
			}
		}
		if value == nil && pending != nil {
			value = *pending
			pending = nil
		}
		if value == nil {
			select {
			case terminal = <-c.terminal:
				value = terminal.message
			case r := <-c.replies:
				value = r
				reply = true
			case e := <-c.events:
				pending = &e
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		b, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if len(b)+1 > MessageLimit {
			if !reply {
				continue
			}
			r := value.(Reply)
			b, _ = json.Marshal(Reply{ID: r.ID, Error: "reply exceeds 1 MiB; narrow the request"})
		}
		b = append(b, '\n')
		for len(b) > 0 {
			n, err := w.Write(b)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			b = b[n:]
		}
		if terminal != nil {
			close(terminal.written)
		}
		if reply {
			<-c.slots
			if value.(Reply).terminal && c.finished != nil {
				c.finished()
			}
		}
	}
}
