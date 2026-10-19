//go:build linux && arm64

package netns

// setns(2) on arm64 (the generic syscall table); package syscall doesn't name it.
const sysSetns = 268
