package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type failureTun struct {
	*testfake.Tun
	read    bool
	trigger chan struct{}
	cause   error
}

func (t *failureTun) ReadPacket(ctx context.Context, b []byte) (int, error) {
	if !t.read {
		return t.Tun.ReadPacket(ctx, b)
	}
	select {
	case <-t.trigger:
		return 0, t.cause
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (t *failureTun) WritePacket(context.Context, []byte) error { return t.cause }

type failureBatchTun struct{ *failureTun }

func (t *failureBatchTun) WriteBatch([][]byte) (int, error) { return 0, t.cause }

func TestTunErrorHandoffAndGenericFatalPaths(t *testing.T) {
	for _, path := range []string{"read", "write", "batch"} {
		for _, mode := range []string{"nil", "declined", "handled"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				cause := errors.New("test TUN failure")
				tun := &failureTun{Tun: testfake.NewTun(), read: path == "read", trigger: make(chan struct{}), cause: cause}
				var device platform.TunDevice = tun
				if path == "batch" {
					device = &failureBatchTun{tun}
				}
				e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return device, nil },
					Routes: &testfake.Routes{}, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
				defer e.Stop(context.Background())
				handoff, fatal := make(chan error, 1), make(chan error, 1)
				if mode != "nil" {
					e.OnTunError = func(err error) bool {
						if mode != "handled" {
							return false
						}
						handoff <- err
						return true
					}
				}
				e.OnFatal = func(err error) { fatal <- err }
				config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
				if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
					t.Fatal(err)
				}
				if path == "read" {
					close(tun.trigger)
				} else {
					e.link.Send([]byte("test output"))
				}
				notice := fatal
				if mode == "handled" {
					notice = handoff
				}
				select {
				case err := <-notice:
					if !errors.Is(err, cause) {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("failure callback missing")
				}
				if mode == "handled" {
					if e.Table.Applied() == nil {
						t.Fatal("platform handoff ran generic cleanup")
					}
					if err := e.Stop(context.Background()); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-fatal:
						t.Fatalf("handled error called OnFatal: %v", err)
					default:
					}
				} else if e.Table.Applied() != nil {
					t.Fatal("generic fatal callback preceded cleanup")
				}
				select {
				case <-tun.Done:
				default:
					t.Fatal("TUN remained open after stop")
				}
			})
		}
	}
}
