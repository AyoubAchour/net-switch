package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

type RPC struct {
	conn    io.ReadWriteCloser
	write   sync.Mutex
	mu      sync.Mutex
	pending map[string]chan rpcReply
	done    chan struct{}
	err     error
	next    atomic.Uint64
}
type rpcReply struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

func NewRPC(c io.ReadWriteCloser) *RPC {
	r := &RPC{conn: c, pending: map[string]chan rpcReply{}, done: make(chan struct{})}
	go r.read()
	return r
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
	// Cancellation closes this connection: an ambiguous mutation is recovered
	// using its durable revision/opId, never retried as a fresh operation.
	stop := context.AfterFunc(ctx, func() { r.fail(ctx.Err()) })
	defer stop()
	r.write.Lock()
	_, err = r.conn.Write(append(b, '\n'))
	r.write.Unlock()
	if err != nil {
		r.fail(err)
		return err
	}
	select {
	case reply := <-ch:
		if reply.Error != "" {
			return fmt.Errorf("IPC: %s", reply.Error)
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
