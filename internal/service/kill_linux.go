package service

import "context"

func ForceStop(ctx context.Context, name string) error {
	if err := systemctl(ctx, "kill", "--kill-whom=all", "--signal=SIGKILL", unit(name)); err != nil {
		return err
	}
	return WaitStopped(ctx, name)
}
