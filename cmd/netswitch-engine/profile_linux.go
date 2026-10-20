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
	done := make(chan struct{})
	var worker sync.WaitGroup
	worker.Go(func() {
		captures := 0
		for {
			select {
			case <-done:
				return
			case <-signals:
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
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	f, err := os.OpenFile(filepath.Join(dir, "memory.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return errors.Join(json.NewEncoder(f).Encode(stats), f.Close())
}
