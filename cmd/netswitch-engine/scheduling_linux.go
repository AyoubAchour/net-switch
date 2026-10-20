//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// Routing must get CPU while the applications it serves are busy. Linux nice
// values belong to threads; use Go's process-wide syscall mechanism so current
// and subsequently-created runtime threads inherit the same normal-scheduler
// priority. An explicit administrator priority is left intact.
func configureScheduling() error {
	threads, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	for _, thread := range threads {
		tid, err := strconv.Atoi(thread.Name())
		if err != nil {
			continue
		}
		raw, err := unix.Getpriority(unix.PRIO_PROCESS, tid)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return err
		}
		// The syscall (unlike libc) returns 20 minus the nice value.
		if raw != 20 {
			log.Printf("routing CPU scheduling: preserving explicit nice %d", 20-raw)
			return nil
		}
	}
	priority := -5
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_SETPRIORITY, unix.PRIO_PROCESS, 0, uintptr(priority)); errno != 0 {
		return fmt.Errorf("set routing CPU scheduling: %w", errno)
	}
	threads, err = os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	checked := 0
	for _, thread := range threads {
		tid, err := strconv.Atoi(thread.Name())
		if err != nil {
			continue
		}
		raw, err := unix.Getpriority(unix.PRIO_PROCESS, tid)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return err
		}
		if 20-raw != priority {
			return fmt.Errorf("routing thread %d has nice %d, want %d", tid, 20-raw, priority)
		}
		checked++
	}
	log.Printf("routing CPU scheduling: nice %d verified on %d threads", priority, checked)
	return nil
}
