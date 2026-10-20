package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func engineDenied() error {
	if lifecycle.Administrator() {
		return errors.New("engine ACL probe was not a standard user")
	}
	status, err := service.Query(service.Engine)
	if err != nil || !status.Running {
		return fmt.Errorf("engine ACL precondition is not live: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := localipc.Dial(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
	if err == nil {
		conn.Close()
		return errors.New("standard user connected to engine")
	}
	if !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("engine connection failed for a reason other than permissions: %w", err)
	}
	return nil
}

func statusCapacity() error {
	if lifecycle.Administrator() {
		return errors.New("status capacity probe was not a standard user")
	}
	before, err := service.Query(service.Control)
	if err != nil || !before.Running {
		return fmt.Errorf("status capacity precondition is not live: %v", err)
	}
	endpoint := localipc.Endpoint{Path: localipc.DefaultPath("status"), Kind: "status", Service: service.Control}
	var connections []*localipc.Conn
	for range 40 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := localipc.Dial(ctx, endpoint)
		cancel()
		if err != nil {
			break
		}
		connections = append(connections, conn)
	}
	for _, conn := range connections {
		conn.Close()
	}
	if len(connections) < 25 {
		return fmt.Errorf("status capacity precondition: only %d clients connected", len(connections))
	}
	// Let accepted handlers observe EOF before asking for another slot. No
	// restart or second burst is allowed to repair the listener under test.
	time.Sleep(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rpc, err := lifecycle.ConnectDesktop(ctx, true)
	if err != nil {
		return fmt.Errorf("status endpoint lost after %d clients: %w", len(connections), err)
	}
	defer rpc.Close()
	if err := rpc.Call(ctx, map[string]any{"method": "status"}, nil); err != nil {
		return fmt.Errorf("status endpoint stopped answering after %d clients: %w", len(connections), err)
	}
	after, err := service.Query(service.Control)
	if err != nil || !after.Running || before.PID != after.PID {
		return fmt.Errorf("status capacity restarted Control: before=%+v after=%+v error=%v", before, after, err)
	}
	fmt.Printf("status listener survived %d standard-user connections without restarting Control\n", len(connections))
	return nil
}
