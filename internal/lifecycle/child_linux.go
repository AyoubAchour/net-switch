package lifecycle

import (
	"os/exec"
	"syscall"
)

func guardedStart(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() {}, nil
}
