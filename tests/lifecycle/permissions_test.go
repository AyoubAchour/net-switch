package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	if len(connections) < 25 {
		return fmt.Errorf("status capacity precondition: only %d clients connected", len(connections))
	}
	fmt.Printf("holding %d connections\n", len(connections))
	// Parent probes fresh owner desktop/CLI/token access before releasing us.
	_, _ = io.Copy(io.Discard, os.Stdin)
	after, err := service.Query(service.Control)
	if err != nil || !after.Running || before.PID != after.PID {
		return fmt.Errorf("status capacity restarted Control: before=%+v after=%+v error=%v", before, after, err)
	}
	fmt.Printf("status listener survived %d standard-user connections without restarting Control\n", len(connections))
	return nil
}

func disconnectBurst() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for range 500 {
		c, err := localipc.Dial(ctx, localipc.Endpoint{Path: localipc.DefaultPath("status"), Kind: "status", Service: service.Control})
		if err != nil {
			return err
		}
		c.Close()
	}
	return nil
}
