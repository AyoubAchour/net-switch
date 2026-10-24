package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

type RPC struct {
	conn    io.ReadWriteCloser
	writes  chan rpcWrite
	mu      sync.Mutex
	pending map[string]chan rpcReply
	done    chan struct{}
	err     error
	next    atomic.Uint64
	// onEvent receives a copy of every message without an id (events and the
	// engine's terminal record). It is installed before the reader starts and
	// must not block.
	onEvent func(*RPC, []byte)
}
type rpcWrite struct {
	ctx  context.Context
	data []byte
}
type rpcError string

func (e rpcError) Error() string { return "IPC: " + string(e) }

type rpcReply struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

func NewRPC(c io.ReadWriteCloser) *RPC { return NewRPCWithEvents(c, nil) }

// NewRPCWithEvents installs the event handler before the reader goroutine
// exists, so no message can arrive while the handler is unset.
func NewRPCWithEvents(c io.ReadWriteCloser, onEvent func(*RPC, []byte)) *RPC {
	r := &RPC{conn: c, writes: make(chan rpcWrite, protocol.Outstanding), pending: map[string]chan rpcReply{}, done: make(chan struct{}), onEvent: onEvent}
	go r.read()
	go r.write()
	return r
}
func (r *RPC) write() {
	for {
		select {
		case <-r.done:
			return
		case w := <-r.writes:
			if w.ctx.Err() != nil {
				continue
			}
			n, err := r.conn.Write(w.data)
			if err == nil && n != len(w.data) {
				err = io.ErrShortWrite
			}
			if err != nil {
				r.fail(err)
				return
			}
		}
	}
}
func (r *RPC) read() {
	scan := bufio.NewScanner(r.conn)
	scan.Buffer(make([]byte, 4096), protocol.MessageLimit+1)
	for scan.Scan() {
		var reply rpcReply
		if err := json.Unmarshal(scan.Bytes(), &reply); err != nil {
			r.fail(err)
			return
		}
		if reply.ID == "" {
			if reply.Error != "" {
				r.fail(rpcError(reply.Error))
				return
			}
			if r.onEvent != nil {
				r.onEvent(r, append([]byte{}, scan.Bytes()...))
			}
			continue
		} // droppable events
		r.mu.Lock()
		ch := r.pending[reply.ID]
		delete(r.pending, reply.ID)
		r.mu.Unlock()
		if ch != nil {
			ch <- reply
		}
	}
	err := scan.Err()
	if err == nil {
		err = io.EOF
	}
	r.fail(err)
}
func (r *RPC) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
		close(r.done)
		r.conn.Close()
	}
}
func (r *RPC) Close() error          { r.fail(io.ErrClosedPipe); return nil }
func (r *RPC) Done() <-chan struct{} { return r.done }
func (r *RPC) Call(ctx context.Context, request map[string]any, result any) error {
	id := strconv.FormatUint(r.next.Add(1), 10)
	request["id"] = id
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(b)+1 > protocol.MessageLimit {
		return errors.New("IPC request exceeds 1 MiB")
	}
	ch := make(chan rpcReply, 1)
	r.mu.Lock()
	if r.err != nil {
		err = r.err
	} else if len(r.pending) >= protocol.Outstanding {
		err = errors.New("too many outstanding requests")
	} else {
		r.pending[id] = ch
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	defer func() { r.mu.Lock(); delete(r.pending, id); r.mu.Unlock() }()
	// A request deadline is not a transport failure. Late replies are dropped
	// by ID; ambiguous mutations retain their durable revision/operation ID.
	select {
	case r.writes <- rpcWrite{ctx, append(b, '\n')}:
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		r.mu.Lock()
		err = r.err
		r.mu.Unlock()
		return err
	}
	select {
	case reply := <-ch:
		if reply.Error != "" {
			return rpcError(reply.Error)
		}
		if result != nil {
			return json.Unmarshal(reply.Result, result)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		// The server may close immediately after its stop acknowledgement.
		select {
		case reply := <-ch:
			if reply.Error != "" {
				return errors.New(reply.Error)
			}
			if result != nil {
				return json.Unmarshal(reply.Result, result)
			}
			return nil
		default:
			r.mu.Lock()
			err := r.err
			r.mu.Unlock()
			return err
		}
	}
}
