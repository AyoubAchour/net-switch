package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func ConnectDesktop(ctx context.Context, status bool) (*RPC, error) {
	kind := "desktop"
	if status {
		kind = "status"
	}
	conn, err := localipc.Dial(ctx, localipc.Endpoint{Path: localipc.DefaultPath(kind), Kind: kind, Service: service.Control})
	if err != nil {
		return nil, err
	}
	return NewRPC(conn), nil
}

// ConfigureAutostart is the per-user installer hook. It writes only the
// enrolled user's Run key/XDG entry; it does not turn routing on.
func ConfigureAutostart(ctx context.Context, mode string) (any, error) {
	if mode != "on" && mode != "off" && mode != "status" {
		return nil, fmt.Errorf("autostart must be on, off or status")
	}
	if err := service.Activate(ctx); err != nil {
		return nil, err
	}
	rpc, err := ConnectDesktop(ctx, false)
	if err != nil {
		return nil, err
	}
	defer rpc.Close()
	if err := rpc.Call(ctx, map[string]any{"method": "session"}, nil); err != nil {
		return nil, err
	}
	if mode == "status" {
		return DesktopCall(ctx, "autostart", nil)
	}
	return DesktopCall(ctx, "autostart-set", map[string]any{"on": mode == "on"})
}
func Desktop(ctx context.Context, show bool) error {
	first := true
	for ctx.Err() == nil {
		connectCtx, stop := context.WithTimeout(ctx, 40*time.Second)
		err := service.Activate(connectCtx)
		if err != nil {
			stop()
			return err
		}
		rpc, err := ConnectDesktop(connectCtx, false)
		stop()
		if err != nil {
			return err
		}
		err = desktopSession(ctx, rpc, show, first)
		rpc.Close()
		if ctx.Err() != nil {
			return nil
		}
		fmt.Println("Net Switch connection lost; reconnecting:", err)
		first = false
		if err := localipc.Pause(ctx, time.Second); err != nil {
			return nil
		}
	}
	return nil
}
func desktopSession(ctx context.Context, rpc *RPC, show, signIn bool) error {
	var session struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "session"}, &session); err != nil {
		return err
	}
	if signIn {
		if err := rpc.Call(ctx, map[string]any{"method": "signin"}, nil); err != nil {
			return err
		}
	} else {
		// Reconnect metadata without turning routing back on after the owner
		// explicitly stopped it.
		if err := rpc.Call(ctx, map[string]any{"method": "desktop-connect"}, nil); err != nil {
			return err
		}
	}
	if show {
		var code string
		if err := rpc.Call(ctx, map[string]any{"method": "pair"}, &code); err != nil {
			return err
		}
		if err := ShowPairing(session.URL+"pair", code); err != nil {
			return err
		}
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rpc.Done():
			return fmt.Errorf("Control restarted")
		case <-tick.C:
			var tasks []DesktopWork
			if err := rpc.Call(ctx, map[string]any{"method": "desktop-poll"}, &tasks); err != nil {
				return err
			}
			for _, task := range tasks {
				value, err := DesktopCall(ctx, task.Operation, task.Args)
				message := ""
				if err != nil {
					message = err.Error()
				}
				if err := rpc.Call(ctx, map[string]any{"method": "desktop-result", "key": task.ID, "value": value, "error": message}, nil); err != nil {
					return err
				}
			}
		}
	}
}
