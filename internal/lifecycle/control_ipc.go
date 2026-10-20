package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/localipc"
)

type controlRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	On     bool   `json:"on"`
	Key    string `json:"key"`
	Value  any    `json:"value"`
	Error  string `json:"error"`
}
type Access struct {
	Core    *control.Core
	Remote  *Remote
	Owner   Owner
	Tokens  *Tokens
	Desktop *DesktopBridge
	Port    int
	Data    string
}

func (a *Access) status() any {
	return map[string]any{"owner": a.Owner, "pending": a.Owner.User == "", "routing": a.Remote.Snapshot().Status, "error": a.Remote.Snapshot().Error, "controlPID": os.Getpid(), "engineInstanceId": a.Remote.Snapshot().Instance}
}
func (a *Access) request(ctx context.Context, peer localipc.Peer, statusOnly bool, session string, r controlRequest) (any, error) {
	if r.Method == "status" {
		return a.status(), nil
	}
	if statusOnly || a.Owner.User == "" || peer.User != a.Owner.User {
		return nil, errors.New("only the enrolled owner may control routing")
	}
	switch r.Method {
	case "session":
		token, err := a.Tokens.Get(session)
		if err != nil {
			return nil, err
		}
		return map[string]any{"token": token, "url": fmt.Sprintf("http://127.0.0.1:%d/", a.Port)}, nil
	case "pair":
		return a.Tokens.Pairing(session)
	case "revoke":
		a.Tokens.Close(session)
		return true, nil
	case "signin":
		a.Desktop.Connect(session)
		return true, a.Core.Routing(ctx, true)
	case "desktop-connect":
		a.Desktop.Connect(session)
		return true, nil
	case "routing":
		return true, a.Core.Routing(ctx, r.On)
	case "desktop-poll":
		return a.Desktop.Poll(session), nil
	case "desktop-result":
		a.Desktop.Complete(session, r.Key, r.Value, r.Error)
		return true, nil
	default:
		return nil, fmt.Errorf("unknown desktop command %q", r.Method)
	}
}
func (a *Access) serve(ctx context.Context, c *localipc.Conn, statusOnly bool) {
	defer c.Close()
	session := randomID()
	if !statusOnly && a.Owner.User != "" && c.Peer.User == a.Owner.User {
		a.Tokens.Open(session)
	}
	defer a.Tokens.Close(session)
	defer a.Desktop.Disconnect(session)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), protocol.MessageLimit+1)
	var write sync.Mutex
	var tasks sync.WaitGroup
	slots := make(chan struct{}, 16)
	defer tasks.Wait()
	for scan.Scan() {
		var r controlRequest
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil || r.ID == "" || len(r.ID) > 128 {
			return
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		tasks.Go(func() {
			defer func() { <-slots }()
			operation, cancel := context.WithTimeout(ctx, 35*time.Second)
			defer cancel()
			value, err := a.request(operation, c.Peer, statusOnly, session, r)
			reply := protocol.Reply{ID: r.ID, Result: value}
			if err != nil {
				reply.Result = nil
				reply.Error = err.Error()
			}
			b, err := json.Marshal(reply)
			if err != nil || len(b) > protocol.MessageLimit {
				b, _ = json.Marshal(protocol.Reply{ID: r.ID, Error: "desktop reply exceeds limit"})
			}
			write.Lock()
			_, err = c.Write(append(b, '\n'))
			write.Unlock()
			if err != nil {
				c.Close()
			}
		})
	}
	// Revocation follows transport closure, even if a queued mutation is
	// finishing under Control's own accepted-operation lifetime.
	a.Tokens.Close(session)
	a.Desktop.Disconnect(session)
	cancel()
}
func accept(ctx context.Context, l localipc.Listener, serve func(*localipc.Conn), log func(string)) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	slots := make(chan struct{}, 32)
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		c, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			clients.Go(func() { defer func() { <-slots }(); serve(c) })
		default:
			c.Close()
			log("IPC connection limit reached")
		}
	}
}
