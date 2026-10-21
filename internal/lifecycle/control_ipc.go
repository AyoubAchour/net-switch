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
	snapshot := a.Remote.Snapshot()
	return map[string]any{"owner": a.Owner, "pending": a.Owner.User == "", "routing": snapshot.Status, "error": snapshot.Error, "controlPID": os.Getpid(), "engineInstanceId": snapshot.Instance, "desktopPID": a.Desktop.PID(), "earlyDisconnects": localipc.EarlyDisconnects.Load()}
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
		return map[string]any{"token": token, "url": fmt.Sprintf("http://127.0.0.1:%d/", a.Port), "ownerName": a.Owner.Name}, nil
	case "pair":
		return a.Tokens.Pairing(session)
	case "revoke":
		a.Tokens.Close(session)
		return true, nil
	case "signin":
		a.Desktop.Connect(session, peer.PID)
		a.Core.DesktopConnected()
		return true, a.Core.SignIn(ctx)
	case "desktop-connect":
		a.Desktop.Connect(session, peer.PID)
		a.Core.DesktopConnected()
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
	// Owner desktop sessions are long-lived; public status connections are
	// short requests. A partial frame does not keep an idle slot alive.
	var idle *time.Timer
	if statusOnly || c.Peer.User != a.Owner.User || a.Owner.User == "" {
		idle = time.AfterFunc(10*time.Second, func() { c.Close() })
		defer idle.Stop()
	}
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), protocol.MessageLimit+1)
	var write sync.Mutex
	var tasks sync.WaitGroup
	slots := make(chan struct{}, 16)
	defer tasks.Wait()
	for scan.Scan() {
		if idle != nil {
			idle.Reset(10 * time.Second)
		}
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
func accept(ctx context.Context, l localipc.Listener, serve func(*localipc.Conn), log func(string), owners ...string) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	owner := ""
	if len(owners) != 0 {
		owner = owners[0]
	}
	limits := &connectionLimits{owner: owner, users: map[string]int{}}
	var clients sync.WaitGroup
	defer func() {
		// A failed listener must reach service recovery even when clients
		// have left their connections idle indefinitely.
		cancel()
		clients.Wait()
	}()
	var peerReport, limitReport rejectionLog
	for {
		c, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, localipc.ErrPeer) {
				peerReport.report(log, err.Error())
				continue
			}
			if ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		if limits.take(c.Peer.User) {
			clients.Go(func() {
				defer limits.release(c.Peer.User)
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				serve(c)
			})
		} else {
			c.Close()
			limitReport.report(log, "IPC connection limit reached; owner and service slots remain reserved")
		}
	}
}

type rejectionLog struct {
	mu         sync.Mutex
	timer      *time.Timer
	suppressed uint64
}

func (r *rejectionLog) report(log func(string), message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.suppressed++
		return
	}
	log(fmt.Sprintf("%s (suppressed since previous report: %d)", message, r.suppressed))
	r.suppressed = 0
	r.timer = time.AfterFunc(10*time.Second, func() { r.flush(log, message) })
}

func (r *rejectionLog) flush(log func(string), message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.suppressed == 0 {
		r.timer = nil
		return
	}
	log(fmt.Sprintf("%s (suppressed since previous report: %d)", message, r.suppressed))
	r.suppressed = 0
	// A final burst gets a summary even if no later rejection arrives.
	r.timer = time.AfterFunc(10*time.Second, func() { r.flush(log, message) })
}

type connectionLimits struct {
	mu     sync.Mutex
	owner  string
	users  map[string]int
	public int
}

func privilegedPeer(user string) bool { return user == "0" || user == "S-1-5-18" }
func (l *connectionLimits) take(user string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	limit := 2
	public := user != l.owner || l.owner == ""
	if privilegedPeer(user) {
		limit, public = 8, false
	} else if !public {
		limit = 32
	}
	if l.users[user] >= limit || public && l.public >= 16 {
		return false
	}
	l.users[user]++
	if public {
		l.public++
	}
	return true
}
func (l *connectionLimits) release(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.users[user]--
	if l.users[user] == 0 {
		delete(l.users, user)
	}
	if (user != l.owner || l.owner == "") && !privilegedPeer(user) {
		l.public--
	}
}
