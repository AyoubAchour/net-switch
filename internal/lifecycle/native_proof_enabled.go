//go:build lifecycle_test

package lifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
)

// This fault only exists in hosted-test builds. The arm/hit/release files are
// in the verified SYSTEM/root-only store. No protocol operation enables it.
type stalledReader struct {
	platform.TunDevice
	data      string
	ioContext context.Context
	stalled   atomic.Bool
	resets    atomic.Uint32
}

func (r *stalledReader) Close() error {
	err := r.TunDevice.Close()
	if runtime.GOOS == "linux" {
		if _, fault := os.Stat(filepath.Join(r.data, "fault-native-retirement")); fault == nil {
			err = errors.Join(err, errors.New("hosted session retirement failure"))
		}
	}
	return err
}

// Preserve the native device's fast paths, cancellation and counters while
// interposing only the read pump. In particular, Linux stats must not vanish.
func (r *stalledReader) Stats() any {
	if device, ok := r.TunDevice.(interface{ Stats() any }); ok {
		return device.Stats()
	}
	return nil
}
func (r *stalledReader) BindIOContext(ctx context.Context) {
	r.ioContext = ctx
	if device, ok := r.TunDevice.(platform.TunIOContext); ok {
		device.BindIOContext(ctx)
	}
}
func (r *stalledReader) BeginClose() {
	nativeProofDelay(r.data, "stop")
	if device, ok := r.TunDevice.(platform.TunCloseStarter); ok {
		device.BeginClose()
	}
}
func (r *stalledReader) RXChecksumVerified(p []byte) bool {
	device, ok := r.TunDevice.(platform.ChecksumVerifier)
	return ok && device.RXChecksumVerified(p)
}
func (r *stalledReader) WriteBatch(packets [][]byte) (int, error) {
	if device, ok := r.TunDevice.(platform.BatchWriter); ok {
		n, err := device.WriteBatch(packets)
		for _, p := range packets[:min(len(packets), max(0, n))] {
			r.observeReset(p)
		}
		return n, err
	}
	ctx := r.ioContext
	if ctx == nil {
		ctx = context.Background()
	}
	for i, p := range packets {
		if err := r.TunDevice.WritePacket(ctx, p); err != nil {
			return i, err
		}
		r.observeReset(p)
	}
	return len(packets), nil
}

func (r *stalledReader) WritePacket(ctx context.Context, p []byte) error {
	err := r.TunDevice.WritePacket(ctx, p)
	if err == nil {
		r.observeReset(p)
	}
	return err
}
func (r *stalledReader) observeReset(p []byte) {
	if !r.stalled.Load() || len(p) < 40 || p[0]>>4 != 4 || p[9] != 6 {
		return
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || len(p) < ihl+20 || p[ihl+13]&4 == 0 {
		return
	}
	if r.resets.Add(1) <= 8 {
		log.Printf("NATIVE_STALL_RST written=true pid=%d at=%s src=%v:%d dst=%v:%d", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano), p[12:16], binary.BigEndian.Uint16(p[ihl:]), p[16:20], binary.BigEndian.Uint16(p[ihl+2:]))
	}
}

func (r *stalledReader) ReadPacket(ctx context.Context, b []byte) (int, error) {
	n, err := r.TunDevice.ReadPacket(ctx, b)
	if err != nil {
		return n, err
	}
	// The hosted Control cutover proof makes the real read pump report the
	// platform's adapter-loss error (Windows: the Wintun removal error, so the
	// genuine exit-3 path runs; Linux: an ordinary pump failure, exit 1).
	removed := filepath.Join(r.data, "fault-native-adapter-removed")
	if os.Rename(removed, removed+".consumed") == nil {
		log.Printf("NATIVE_READ_FAULT pid=%d kind=adapter-removed at=%s", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
		return 0, nativeProofReadFault()
	}
	arm := filepath.Join(r.data, "fault-native-forwarding")
	if os.Rename(arm, arm+".consumed") != nil {
		return n, nil
	}
	r.stalled.Store(true)
	log.Printf("NATIVE_READ_STALLED pid=%d at=%s bytes=%d", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano), n)
	if err := Save(filepath.Join(r.data, "native-forwarding-hit.json"), map[string]any{"pid": os.Getpid(), "bytes": n}); err != nil {
		return 0, err
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(r.data, "native-forwarding-release")); err == nil {
			return n, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-tick.C:
		}
	}
}

func configureNativeProof(data string, options *host.Options) error {
	options.RetirementError = func() error {
		if _, err := os.Stat(filepath.Join(data, "fault-native-retirement")); err == nil {
			return errors.New("hosted session retirement failure")
		}
		return nil
	}
	var probeExhausted atomic.Bool
	options.ProbeError = func() error {
		if !probeExhausted.Swap(false) {
			return nil
		}
		if runtime.GOOS == "windows" {
			return syscall.Errno(10024)
		} // WSAEMFILE
		return syscall.EMFILE
	}
	if f, err := os.Open(filepath.Join(data, "probe-test-ca.pem")); err == nil {
		b, readErr := io.ReadAll(io.LimitReader(f, (64<<10)+1))
		closeErr := f.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if len(b) > 64<<10 || !roots.AppendCertsFromPEM(b) {
			return errors.New("invalid hosted probe CA")
		}
		options.ProbeTLS = &tls.Config{RootCAs: roots}
	} else if !os.IsNotExist(err) {
		return err
	}
	options.Configure = func(server *protocol.Server, table *flows.Table) {
		server.TestFault = func(ctx context.Context, b json.RawMessage) (any, error) {
			var request struct {
				Kind     string          `json:"kind"`
				Revision policy.Revision `json:"revision"`
			}
			if err := json.Unmarshal(b, &request); err != nil {
				return nil, err
			}
			if request.Kind == "restart-routing" {
				return true, server.RestartForTest(ctx, request.Revision)
			}
			if request.Kind == "idle-error" {
				return true, server.IdleErrorForTest(ctx)
			}
			if request.Kind == "log-flood" {
				logger, ok := log.Writer().(*supervisor.Log)
				if !ok {
					return nil, errors.New("child bounded logger unavailable")
				}
				for range 512 {
					logger.Write(make([]byte, 4096))
				}
				return map[string]uint64{"dropped": logger.Dropped.Load()}, nil
			}
			if request.Kind == "probe-exhaustion" {
				probeExhausted.Store(true)
				return true, nil
			}
			if request.Kind == "kernel-sandbox" {
				return nativeKernelSandboxEvidence(server.Instance)
			}
			if request.Kind != "totals-capacity" {
				return nil, errors.New("unknown hosted native fault")
			}
			if err := table.SeedAccountingFixture(); err != nil {
				return nil, err
			}
			return table.Stats(), nil
		}
	}
	var ready atomic.Bool
	progress := options.Progress
	options.Progress = func(stage string) {
		if progress != nil {
			progress(stage)
		}
		if stage == "ready-callback-end" {
			ready.Store(true)
		}
		_ = os.WriteFile(filepath.Join(data, "native-startup-phase.txt"), []byte(time.Now().UTC().Format(time.RFC3339Nano)+" "+stage), 0600)
	}
	time.AfterFunc(25*time.Second, func() {
		if ready.Load() {
			return
		}
		b := make([]byte, 256<<10)
		n := runtime.Stack(b, true)
		_ = os.WriteFile(filepath.Join(data, "native-startup-stacks.txt"), b[:n], 0600)
	})
	options.WrapTun = func(tun platform.TunDevice) platform.TunDevice {
		nativeProofDelay(data, "start")
		return &stalledReader{TunDevice: tun, data: data}
	}
	return nil
}

func nativeProofDelay(data, phase string) {
	path := filepath.Join(data, "fault-native-"+phase+"-delay")
	var milliseconds int
	if Read(path, &milliseconds) != nil || milliseconds < 1 || milliseconds > 60000 {
		return
	}
	if os.Rename(path, path+".consumed") != nil {
		return
	}
	log.Printf("NATIVE_LIFECYCLE_DELAY phase=%s milliseconds=%d pid=%d", phase, milliseconds, os.Getpid())
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)
}

func nativeProofBeforeReady(data string) error {
	if _, err := os.Stat(filepath.Join(data, "fault-native-startup-exit")); err == nil {
		return errors.New("hosted startup death before readiness")
	}
	return nil
}
func nativeProofLogSink(ctx context.Context, data string, report func(string)) func(string) {
	return func(s string) {
		path := filepath.Join(data, "fault-native-log-sink")
		if _, err := os.Stat(path); err == nil {
			_ = Save(path+".hit", map[string]int{"pid": os.Getpid()})
			for {
				if _, err := os.Stat(path); os.IsNotExist(err) {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
		report(s)
	}
}

// Hosted-only: attempt write opens without writing any bytes. This executes
// with the installed Engine's actual identity, mount namespace and sandbox.
func nativeKernelSandboxEvidence(instance string) (any, error) {
	if runtime.GOOS != "linux" || len(instance) != 32 {
		return nil, errors.New("Linux native sandbox proof requires a live instance")
	}
	result := map[string]string{}
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv6/conf/all/disable_ipv6", "/proc/sys/net/ipv6/conf/default/disable_ipv6",
		"/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/default/accept_ra",
		"/proc/sys/net/ipv6/conf/lo/disable_ipv6",
		"/sys/class/net/lo/mtu", "/sys/fs/cgroup/cgroup.procs",
		"/proc/sys/net/ipv6/conf/ns" + instance[:10] + "/disable_ipv6",
	} {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		switch {
		case err == nil:
			if err := f.Close(); err != nil {
				return nil, err
			}
			result[path] = "writable"
		case errors.Is(err, syscall.EROFS):
			result[path] = "read-only"
		default:
			result[path] = err.Error()
		}
	}
	return result, nil
}

type nativeProofOutcome struct{}

func (nativeProofOutcome) Error() string       { return "hosted completed outcome 3" }
func (nativeProofOutcome) EngineExitCode() int { return 3 }
func nativeProofExit(data string) error {
	if _, err := os.Stat(filepath.Join(data, "fault-native-exit3")); err == nil {
		return nativeProofOutcome{}
	}
	return nil
}

func nativeProofRecovery(data string) error {
	if _, err := os.Stat(filepath.Join(data, "fault-native-recovery")); err == nil {
		return errors.New("hosted recovery failure before OS cleanup")
	}
	return nil
}
