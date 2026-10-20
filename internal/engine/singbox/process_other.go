//go:build !windows

package singbox

import "os/exec"

func hide(*exec.Cmd) {}
