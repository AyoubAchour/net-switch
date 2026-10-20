//go:build !windows

package main

import "os/exec"

func hide(*exec.Cmd) {}
