package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
)

const routeOwner = "S-1-5-21-1-2-3-1001"

// routeListener stands in for one Control endpoint. When flooded it models
// the Windows public status pipe while another user keeps its only listening
// instance occupied with idle opens: every accept cycle spends the bounded
// identity read on an attacker handle, and a legitimate client never gets the
// instance before its own deadline. The accept loop and request handling that
// run on top of it are the real ones.
type routeListener struct {
	kind     string
	flooded  bool
	conns    chan *localipc.Conn
	closed   chan struct{}
	once     sync.Once
	idle     atomic.Uint64
	accepted atomic.Uint64
}

func (l *routeListener) Accept(ctx context.Context) (*localipc.Conn, error) {
	if l.flooded {
		select {
		case <-time.After(250 * time.Millisecond):
			l.idle.Add(1)
			return nil, fmt.Errorf("%w: pipe identity handshake: idle open", localipc.ErrPeer)
		case <-l.closed:
			return nil, os.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case c := <-l.conns:
		l.accepted.Add(1)
		return c, nil
	case <-l.closed:
		return nil, os.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (l *routeListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

type routeServer struct {
	listeners map[string]*routeListener
	refuse    map[string]error // dial errors raised before any instance is used
	peer      localipc.Peer
	mu        sync.Mutex
	dialed    []string
}

func newRouteServer(t *testing.T, peer localipc.Peer, floodPublic bool) *routeServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &routeServer{listeners: map[string]*routeListener{}, refuse: map[string]error{}, peer: peer}
	access := &Access{Remote: NewRemote(ctx, func(string) {}), Desktop: &DesktopBridge{}, Owner: Owner{User: routeOwner, Name: "Owner"}, Tokens: NewTokens()}
	var loops sync.WaitGroup
	for _, kind := range []string{"desktop", "status"} {
		l := &routeListener{kind: kind, flooded: kind == "status" && floodPublic, conns: make(chan *localipc.Conn), closed: make(chan struct{})}
		s.listeners[kind] = l
		loops.Go(func() {
			if err := accept(ctx, l, func(c *localipc.Conn) { access.serve(ctx, c, kind == "status") }, func(string) {}, routeOwner); err != nil {
				t.Error(kind, "accept loop failed:", err)
			}
		})
	}
	old := dialIPC
	dialIPC = s.dial
	t.Cleanup(func() { dialIPC = old; cancel(); loops.Wait() })
	return s
}

func (s *routeServer) dial(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
	s.mu.Lock()
	s.dialed = append(s.dialed, e.Kind)
	s.mu.Unlock()
	if e.Path != localipc.DefaultPath(e.Kind) || e.Service == "" {
		return nil, fmt.Errorf("unexpected endpoint %+v", e)
	}
	if err := s.refuse[e.Kind]; err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	select {
	case s.listeners[e.Kind].conns <- &localipc.Conn{ReadWriteCloser: server, Peer: s.peer}:
		return &localipc.Conn{ReadWriteCloser: client, Peer: localipc.Peer{User: "S-1-5-18"}}, nil
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	}
}

func (s *routeServer) dials() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.dialed, ",")
}

// Owner `netswitchctl status` and the administrator's enrollment settle check
// must not depend on the endpoint every signed-in user can occupy.
func TestStatusReadersAvoidFloodedPublicEndpoint(t *testing.T) {
	for _, peer := range []localipc.Peer{{User: routeOwner, PID: 41}, {User: "S-1-5-18", PID: 42}} {
		t.Run(peer.User, func(t *testing.T) {
			s := newRouteServer(t, peer, true)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			started := time.Now()
			active, err := installedOwnerServices().activeOwner(ctx)
			if err != nil || active != routeOwner {
				t.Fatalf("enrollment settle check during public flood: owner=%q err=%v dials=%s", active, err, s.dials())
			}
			if err := Ctl([]string{"status"}); err != nil {
				t.Fatalf("netswitchctl status during public flood: %v dials=%s", err, s.dials())
			}
			public := s.listeners["status"]
			wait := time.Until(started.Add(600 * time.Millisecond))
			if wait > 0 {
				time.Sleep(wait)
			}
			if public.idle.Load() == 0 || public.accepted.Load() != 0 {
				t.Fatalf("flood precondition: idle=%d public accepted=%d", public.idle.Load(), public.accepted.Load())
			}
			if got := s.dials(); strings.Contains(got, "status") {
				t.Fatal("status reader dialled the public endpoint despite protected access:", got)
			}
		})
	}
}

// A user without protected rights keeps the public, status-only path, and the
// read never activates Control.
func TestStatusReaderFallsBackToPublicStatusOnly(t *testing.T) {
	other := localipc.Peer{User: "S-1-5-21-1-2-3-1002", PID: 43}
	s := newRouteServer(t, other, false)
	s.refuse["desktop"] = fmt.Errorf("open protected pipe: %w", fs.ErrPermission)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rpc, err := ConnectStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	var state struct {
		Owner Owner `json:"owner"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "status"}, &state); err != nil || state.Owner.User != routeOwner {
		t.Fatal("public status", state, err)
	}
	if err := rpc.Call(ctx, map[string]any{"method": "routing", "on": true}, nil); err == nil {
		t.Fatal("public status connection accepted a routing change")
	}
	if got := s.dials(); got != "desktop,status" {
		t.Fatal("unexpected dial order", got)
	}
}

// Any other protected-dial failure (an unverified server, an expired deadline)
// is reported instead of being retried on the public endpoint.
func TestStatusReaderReportsProtectedFailures(t *testing.T) {
	s := newRouteServer(t, localipc.Peer{User: routeOwner, PID: 44}, false)
	refused := errors.New("pipe PID 7 is not the NetSwitch service PID 8")
	s.refuse["desktop"] = refused
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if rpc, err := ConnectStatus(ctx); !errors.Is(err, refused) {
		if rpc != nil {
			rpc.Close()
		}
		t.Fatal("protected failure hidden by fallback", err)
	}
	if got := s.dials(); got != "desktop" {
		t.Fatal("unexpected fallback", got)
	}
}
