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
