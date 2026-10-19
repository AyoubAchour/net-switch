//go:build linux && amd64

package netns

// setns(2) on x86_64; package syscall doesn't name it.
const sysSetns = 308
