package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func unit(name string) string {
	if name == Engine {
		return "netswitch-engine.service"
	}
	return "netswitch.service"
}
func Run(_ string, program Program) error {
	if os.Geteuid() != 0 {
		return errors.New("system service requires root")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt, syscall.SIGUSR1)
	defer signal.Stop(signals)
	go func() {
		select {
		case s := <-signals:
			if s == syscall.SIGUSR1 {
				cancel(ErrRestart)
			} else {
				cancel(nil)
			}
		case <-ctx.Done():
		}
	}()
	return program(ctx, func() {
		if address := os.Getenv("NOTIFY_SOCKET"); address != "" {
			c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
			if err == nil {
				_, _ = c.Write([]byte("READY=1"))
				c.Close()
			}
		}
	})
}
func systemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	cmd.Env = ChildEnvironment()
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %w: %s", args, err, b)
	}
	return nil
}
func Start(ctx context.Context, name string) error { return systemctl(ctx, "start", unit(name)) }
func RequestRestart(ctx context.Context, name string) error {
	return systemctl(ctx, "kill", "--kill-whom=main", "--signal=SIGUSR1", unit(name))
}

// Connecting to netswitch.socket activates Control without granting the
// desktop root or polkit privileges.
func Activate(ctx context.Context) error {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/netswitch/desktop.sock")
	if err != nil {
		return err
	}
	return c.Close()
}
func Stop(ctx context.Context, name string) error { return systemctl(ctx, "stop", unit(name)) }
func Query(name string) (Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=MainPID,ActiveState,SubState", unit(name))
	cmd.Env = ChildEnvironment()
	b, err := cmd.Output()
	if err != nil {
		return Status{}, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	n, err := strconv.ParseUint(values["MainPID"], 10, 32)
	return Status{PID: uint32(n), Running: values["ActiveState"] == "active" && values["SubState"] == "running" && n != 0, Stopped: n == 0 && (values["ActiveState"] == "inactive" || values["ActiveState"] == "failed")}, err
}
func SetOwner(string) error              { return nil }
func ReportError(name string, err error) { fmt.Fprintf(os.Stderr, "%s: %v\n", name, err) }
func quoted(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
func Install(c Config) error {
	if os.Geteuid() != 0 {
		return errors.New("install requires root")
	}
	for _, path := range []string{c.Directory, c.Data} {
		if strings.ContainsAny(path, "\n\r%") || !filepath.IsAbs(path) {
			return errors.New("invalid service path")
		}
	}
	run := func(file string) string { return quoted(filepath.Join(c.Directory, file)) }
	common := "\nUser=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nProtectClock=yes\nProtectHostname=yes\nProtectKernelLogs=yes\nRestrictNamespaces=yes\nLockPersonality=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nDevicePolicy=closed\nReadWritePaths=" + quoted(c.Data) + " /run/netswitch\n"
	// /proc/<pid>/exe and fd links for other UIDs require the ptrace read
	// permission. Routing is machine-wide, including other users' apps.
	readCapabilities := "CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"
	units := map[string]string{
		"netswitch.socket":         "[Unit]\nDescription=Net Switch local desktop socket\n[Socket]\nListenStream=/run/netswitch/desktop.sock\nSocketMode=0666\nDirectoryMode=0755\nRemoveOnStop=yes\n[Install]\nWantedBy=sockets.target\n",
		"netswitch.service":        "[Unit]\nDescription=Net Switch Control\nRequires=netswitch.socket\nAfter=netswitch.socket\nStartLimitIntervalSec=0\n[Service]\nType=notify\nExecStart=" + run("netswitch") + " service --data " + quoted(c.Data) + "\nRestart=on-failure\nRestartSec=1s\nRestartSteps=4\nRestartMaxDelaySec=60s\nKillMode=control-group\nTimeoutStopSec=40s\nCapabilityBoundingSet=CAP_CHOWN " + readCapabilities + "\n" + common,
		"netswitch-engine.service": "[Unit]\nDescription=Net Switch Engine\nStartLimitIntervalSec=0\n[Service]\nType=notify\nExecStart=" + run("netswitch-engine") + " service --data " + quoted(c.Data) + "\nExecStopPost=" + run("netswitchctl") + " cleanup --engine --data " + quoted(c.Data) + "\nRestart=no\nKillMode=mixed\nTimeoutStopSec=30s\nCapabilityBoundingSet=" + readCapabilities + "\nDeviceAllow=/dev/net/tun rw\n" + common,
	}
	if err := os.MkdirAll("/run/netswitch", 0755); err != nil {
		return err
	}
	for name, text := range units {
		path := filepath.Join("/etc/systemd/system", name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		_, err = f.WriteString(text)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	ctx := context.Background()
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return systemctl(ctx, "enable", "--now", "netswitch.socket")
}
func Uninstall(ctx context.Context) error {
	for _, name := range []string{Control, Engine} {
		if err := Stop(ctx, name); err != nil {
			return err
		}
	}
	if err := systemctl(ctx, "disable", "--now", "netswitch.socket"); err != nil {
		return err
	}
	for _, name := range []string{"netswitch.service", "netswitch-engine.service", "netswitch.socket"} {
		if err := os.Remove(filepath.Join("/etc/systemd/system", name)); err != nil {
			return err
		}
	}
	return systemctl(ctx, "daemon-reload")
}
