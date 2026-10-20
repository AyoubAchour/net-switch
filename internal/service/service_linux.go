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
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
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
	b, err := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %w: %s", args, err, b)
	}
	return nil
}
func Start(ctx context.Context, name string) error { return systemctl(ctx, "start", unit(name)) }

// Connecting to netswitch.socket activates Control without granting the
// desktop root or polkit privileges.
func Activate(context.Context) error              { return nil }
func Stop(ctx context.Context, name string) error { return systemctl(ctx, "stop", unit(name)) }
func Query(name string) (Status, error) {
	b, err := exec.Command("/usr/bin/systemctl", "show", "--property=MainPID", "--value", unit(name)).Output()
	if err != nil {
		return Status{}, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	return Status{PID: uint32(n), Running: n != 0}, err
}
func SetOwner(string) error { return nil }
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
	common := "\nUser=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nReadWritePaths=" + quoted(c.Data) + " /run/netswitch\n"
	units := map[string]string{
		"netswitch.socket":         "[Unit]\nDescription=Net Switch local desktop socket\n[Socket]\nListenStream=/run/netswitch/desktop.sock\nSocketMode=0666\nDirectoryMode=0755\nRemoveOnStop=yes\n[Install]\nWantedBy=sockets.target\n",
		"netswitch.service":        "[Unit]\nDescription=Net Switch Control\nRequires=netswitch.socket\nAfter=netswitch.socket\nStartLimitIntervalSec=0\n[Service]\nType=notify\nExecStart=" + run("netswitch") + " service --data " + quoted(c.Data) + "\nRestart=on-failure\nRestartSec=1s\nKillMode=control-group\nTimeoutStopSec=40s\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_KILL CAP_SETUID CAP_SETGID\n" + common,
		"netswitch-engine.service": "[Unit]\nDescription=Net Switch Engine\n[Service]\nType=notify\nExecStart=" + run("netswitch-engine") + " service --data " + quoted(c.Data) + "\nExecStopPost=" + run("netswitchctl") + " cleanup --engine --data " + quoted(c.Data) + "\nRestart=no\nKillMode=mixed\nTimeoutStopSec=30s\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH\n" + common,
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
