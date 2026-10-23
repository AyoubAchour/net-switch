package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

const PrivateLimit = 16 << 10

// Only inherited pipe capabilities carry these messages. Public native IPC
// never parses this envelope. At most one request is in flight per direction.
type Message struct {
	Seq      uint64 `json:"seq,omitempty"`
	Kind     string `json:"kind"`
	PID      uint32 `json:"pid,omitempty"`
	Handle   uint64 `json:"handle,omitempty"`
	Instance string `json:"instance,omitempty"`
	Code     int    `json:"code,omitempty"`
	Error    string `json:"error,omitempty"`
	State    string `json:"state,omitempty"`
	Index    int    `json:"index,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Key      string `json:"key,omitempty"`
}

type Channel struct {
	read   io.ReadCloser
	write  io.WriteCloser
	input  chan Message
	output chan privateWrite
	done   chan struct{}
	once   sync.Once
}

type privateWrite struct {
	bytes   []byte
	written chan error
}

func NewChannel(read io.ReadCloser, write io.WriteCloser) *Channel {
	c := &Channel{read: read, write: write, input: make(chan Message, 8), output: make(chan privateWrite, 8), done: make(chan struct{})}
	go c.receive()
	go func() {
		defer c.Close()
		for {
			select {
			case b := <-c.output:
				err := Write(write, b.bytes)
				if b.written != nil {
					b.written <- err
				}
				if err != nil {
					return
				}
			case <-c.done:
				return
			}
		}
	}()
	return c
}
func (c *Channel) Close()                   { c.once.Do(func() { close(c.done); go c.read.Close(); go c.write.Close() }) }
func (c *Channel) Done() <-chan struct{}    { return c.done }
func (c *Channel) Messages() <-chan Message { return c.input }
func (c *Channel) receive() {
	defer c.Close()
	defer close(c.input)
	r := bufio.NewReaderSize(c.read, 4096)
	for {
		b, err := Line(r, PrivateLimit)
		if err != nil {
			return
		}
		var m Message
		if json.Unmarshal(b, &m) != nil {
			return
		}
		select {
		case c.input <- m:
		case <-c.done:
			return
		default:
			return
		}
	}
}
func (c *Channel) Send(ctx context.Context, m Message) error {
	return c.send(ctx, m, nil)
}

// Flush waits for the small completion record to reach the inherited pipe,
// not for the host to run. A hung host cannot delay the child's lease cleanup.
func (c *Channel) Flush(ctx context.Context, m Message) error {
	written := make(chan error, 1)
	if err := c.send(ctx, m, written); err != nil {
		return err
	}
	select {
	case err := <-written:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return io.ErrClosedPipe
	}
}
func (c *Channel) send(ctx context.Context, m Message, written chan error) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b)+1 > PrivateLimit {
		return errors.New("private supervisor message exceeds bound")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return io.ErrClosedPipe
	case c.output <- privateWrite{append(b, '\n'), written}:
		return nil
	default:
		c.Close()
		return errors.New("private supervisor queue exhausted")
	}
}
