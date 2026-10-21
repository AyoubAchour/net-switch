//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Opt-in diagnostics use the production binary and add no hooks to lookup or
// packet I/O. A signal takes the snapshot while callers still hold their flows.
func startProfiles(dir string, cpu, execution bool) (func(), error) {
	if dir == "" {
		if cpu || execution {
			return nil, errors.New("profiling requires --profile-dir")
		}
		return func() {}, nil
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !filepath.IsAbs(dir) || !st.IsDir() || st.Mode().Perm()&0077 != 0 || !ok || sys.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("profile directory must be absolute, private and owned by the engine user")
	}
	var cpuFile *os.File
	previousMutexRate := 0
	if cpu {
		cpuFile, err = os.OpenFile(filepath.Join(dir, "cpu.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			cpuFile.Close()
			return nil, err
		}
		runtime.SetBlockProfileRate(1000000)
		previousMutexRate = runtime.SetMutexProfileFraction(100)
	}
	stopTrace := func() {}
	if execution {
		file, traceErr := os.OpenFile(filepath.Join(dir, "runtime.trace"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if traceErr == nil {
			traceErr = trace.Start(file)
			if traceErr != nil {
				file.Close()
			}
		}
		if traceErr != nil {
			if cpuFile != nil {
				pprof.StopCPUProfile()
				cpuFile.Close()
				runtime.SetBlockProfileRate(0)
				runtime.SetMutexProfileFraction(previousMutexRate)
			}
			return nil, traceErr
		}
		// Enough to capture the admission burst without an unbounded trace
		// when a diagnostic service is left running. Disabled by default.
		finish := sync.OnceFunc(func() { trace.Stop(); file.Close() })
		timer := time.AfterFunc(5*time.Second, finish)
		stopTrace = func() { timer.Stop(); finish() }
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	if execution {
		signal.Notify(signals, syscall.SIGUSR2)
	}
	done := make(chan struct{})
	var worker sync.WaitGroup
	worker.Go(func() {
		captures := 0
		probeTraces := 0
		for {
			select {
			case <-done:
				return
			case sig := <-signals:
				if sig == syscall.SIGUSR2 {
					// The initial five-second trace misses post-load probes.
					// An opt-in diagnostic request captures a fresh bounded window.
					stopTrace()
					probeTraces++
					file, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("runtime-probe-%03d.trace", probeTraces)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if err == nil {
						err = trace.Start(file)
						if err != nil {
							file.Close()
						}
					}
					if err != nil {
						fmt.Fprintln(os.Stderr, "capture probe trace:", err)
						continue
					}
					finish := sync.OnceFunc(func() { trace.Stop(); file.Close() })
					timer := time.AfterFunc(5*time.Second, finish)
					stopTrace = func() { timer.Stop(); finish() }
					ready, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("trace-ready-%03d", probeTraces)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if err == nil {
						err = ready.Close()
					}
					if err != nil {
						fmt.Fprintln(os.Stderr, "acknowledge probe trace:", err)
					}
					continue
				}
				captures++
				target := dir
				if captures > 1 {
					target = filepath.Join(dir, fmt.Sprintf("sample-%03d", captures))
					if err := os.Mkdir(target, 0700); err != nil {
						fmt.Fprintln(os.Stderr, "capture profiles:", err)
						continue
					}
				}
				if err := writeProfiles(target); err != nil {
					fmt.Fprintln(os.Stderr, "capture profiles:", err)
				}
			}
		}
	})
	return func() {
		signal.Stop(signals)
		close(done)
		worker.Wait()
		stopTrace()
		if cpuFile != nil {
			pprof.StopCPUProfile()
			cpuFile.Close()
			runtime.SetBlockProfileRate(0)
			runtime.SetMutexProfileFraction(previousMutexRate)
			for _, name := range []string{"block", "mutex"} {
				f, err := os.OpenFile(filepath.Join(dir, name+".pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err == nil {
					err = errors.Join(pprof.Lookup(name).WriteTo(f, 0), f.Close())
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "capture contention profile:", err)
				}
			}
		}
	}, nil
}

func writeProfiles(dir string) error {
	runtime.GC()
	// Read immediately after GC, before profile serialization allocates.
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	for _, name := range []string{"heap", "goroutine"} {
		f, err := os.OpenFile(filepath.Join(dir, name+".pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		err = pprof.Lookup(name).WriteTo(f, 0)
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, "memory.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	rss, socketBytes, rssValid, socketsValid := profileOSMemory()
	return errors.Join(json.NewEncoder(f).Encode(struct {
		runtime.MemStats
		RSS, KernelSocketBytes      uint64
		RSSValid, KernelSocketValid bool
	}{stats, rss, socketBytes, rssValid, socketsValid}), f.Close())
}

func profileOSMemory() (rss, sockets uint64, rssValid, socketsValid bool) {
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 1 {
			pages, parseErr := strconv.ParseUint(fields[1], 10, 64)
			rss = pages * uint64(os.Getpagesize())
			rssValid = parseErr == nil
		}
	}
	// sockstat's TCP/UDP mem fields are pages and include both families.
	if data, err := os.ReadFile("/proc/net/sockstat"); err == nil {
		socketsValid = true
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			for i := 1; i+1 < len(fields); i += 2 {
				if fields[i] == "mem" {
					pages, parseErr := strconv.ParseUint(fields[i+1], 10, 64)
					socketsValid = socketsValid && parseErr == nil
					sockets += pages * uint64(os.Getpagesize())
				}
			}
		}
	}
	return
}
