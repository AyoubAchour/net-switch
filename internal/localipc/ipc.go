// Package localipc authenticates both ends of Net Switch's local transports.
// Application permissions are checked separately, on every request.
package localipc

import (
	"context"
	"errors"
	"io"
	"time"
)

var ErrPeer = errors.New("IPC peer could not be authenticated")

type Peer struct {
	User    string `json:"user"`
	PID     uint32 `json:"pid"`
	Session uint32 `json:"session"`
}

type Conn struct {
	io.ReadWriteCloser
	Peer Peer
}

type Listener interface {
	Accept(context.Context) (*Conn, error)
	Close() error
}

type Endpoint struct {
	Path    string
	Kind    string // desktop, status, engine
	Owner   string
	Service string
}

func Pause(ctx context.Context, duration time.Duration) error {
	t := time.NewTimer(duration)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
