//go:build linux

package nsengine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

type engineProcess struct {
	cmd                                  *exec.Cmd
	done                                 chan struct{}
	err                                  error
	socket, temporary, state, netns, log string
	profiles                             string
}

func (d *Driver) launch(ctx context.Context, env engine.Env) error {
	if d.running() {
		return errors.New("engine already running")
	}
	if d.session != nil {
		d.session.SetAutoRenew(false)
	}
	if d.process != nil {
		os.RemoveAll(d.process.temporary)
	}
	if err := os.MkdirAll(env.WorkDir, 0700); err != nil {
		return err
	}
	temp, err := os.MkdirTemp("", "nse-")
	if err != nil {
		return err
	}
	p := &engineProcess{done: make(chan struct{}), temporary: temp, socket: filepath.Join(temp, "engine.sock"), state: filepath.Join(env.WorkDir, "state"), netns: env.Netns, log: filepath.Join(env.WorkDir, "engine.log")}
	p.profiles, err = os.MkdirTemp(env.WorkDir, "profiles-")
	if err != nil {
		os.RemoveAll(temp)
		return err
	}
	f, err := os.OpenFile(p.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		os.RemoveAll(temp)
		return err
	}
	// Preserve /sys/fs/cgroup while isolating the fixture's resolver mount.
	// ip netns exec remounts all of /sys and hides cgroup2. Every path below
	// is a separate positional argument; no path becomes shell source.
	const launch = `if [ -f "$1" ]; then mount --bind "$1" /etc/resolv.conf || exit; fi; shift; exec "$@"`
	p.cmd = exec.Command("nsenter", "--net="+filepath.Join("/run/netns", env.Netns), "--", "unshare", "--mount", "--propagation", "private", "--", "sh", "-c", launch, "nsengine", filepath.Join("/etc/netns", env.Netns, "resolv.conf"), d.exe.Path, "run", "--socket", p.socket, "--state-dir", p.state)
	p.cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(filepath.Dir(env.WorkDir), "inet", "probe-ca.pem"))
	p.cmd.Args = append(p.cmd.Args, "--profile-dir", p.profiles)
	if os.Getenv("NSACCEPT_PROFILE") == "true" {
		p.cmd.Args = append(p.cmd.Args, "--cpu-profile")
	}
	p.cmd.Stdout = f
	p.cmd.Stderr = f
	if err := p.cmd.Start(); err != nil {
		f.Close()
		os.RemoveAll(temp)
		return err
	}
	d.process = p
	go func() {
		p.err = p.cmd.Wait()
		f.Close()
		if p.err != nil && env.Logf != nil {
			data, _ := os.ReadFile(p.log)
			if len(data) > 4096 {
				data = data[len(data)-4096:]
			}
			env.Logf("engine exited: %v\n%s", p.err, data)
		}
		close(p.done)
	}()
	d.call = func(ctx context.Context, r protocol.Request) ([]byte, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", p.socket)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		deadline := time.Now().Add(15 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		c.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		if err := json.NewEncoder(c).Encode(r); err != nil {
			return nil, err
		}
		reader := bufio.NewReader(c)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return nil, err
			}
			if len(line) > protocol.MessageLimit {
				return nil, errors.New("oversized engine reply")
			}
			var reply struct {
				ID    string `json:"id"`
				Event string `json:"event"`
			}
			if err := json.Unmarshal(line, &reply); err != nil {
				return nil, err
			}
			if reply.ID == r.ID {
				return line, nil
			}
			if reply.Event == "" {
				return nil, fmt.Errorf("reply for unexpected request %q", reply.ID)
			}
		}
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(p.socket); err == nil {
			return nil
		}
		select {
		case <-p.done:
			return fmt.Errorf("engine exited before opening its socket: %v (log %s)", p.err, p.log)
		case <-ctx.Done():
			p.cmd.Process.Kill()
			return ctx.Err()
		case <-deadline.C:
			p.cmd.Process.Kill()
			return fmt.Errorf("engine didn't open its socket (log %s)", p.log)
		case <-tick.C:
		}
	}
}

func (d *Driver) CaptureProfiles(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running() {
		return errors.New("profile capture requires a running engine")
	}
	if err := d.process.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		return err
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if data, err := os.ReadFile(filepath.Join(d.process.profiles, "memory.json")); err == nil && json.Valid(data) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.process.done:
			return errors.New("engine exited during profile capture")
		case <-tick.C:
		}
	}
}

func (d *Driver) ResolverContents() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running() {
		return "", errors.New("engine is not running")
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/etc/resolv.conf", d.process.cmd.Process.Pid))
	return string(b), err
}
func (d *Driver) running() bool {
	if d.process == nil {
		return false
	}
	select {
	case <-d.process.done:
		return false
	default:
		return true
	}
}
func (d *Driver) logPath() string {
	if d.process == nil {
		return ""
	}
	return d.process.log
}
func (d *Driver) crash() error {
	if d.session != nil {
		d.session.SetAutoRenew(false)
	}
	if !d.running() {
		return errors.New("engine not running")
	}
	if err := d.process.cmd.Process.Kill(); err != nil {
		return err
	}
	<-d.process.done
	return nil
}
func (d *Driver) waitExit(ctx context.Context) error {
	if d.process == nil {
		return nil // an injected in-memory transport has no child process
	}
	select {
	case <-d.process.done:
		return d.process.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (d *Driver) cleanup(ctx context.Context) error {
	if d.process == nil {
		return nil
	}
	p := d.process
	cmd := exec.CommandContext(ctx, "nsenter", "--net="+filepath.Join("/run/netns", p.netns), "--", d.exe.Path, "cleanup", "--state-dir", p.state)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("engine cleanup: %w: %s", err, out)
	}
	return os.RemoveAll(p.temporary)
}
