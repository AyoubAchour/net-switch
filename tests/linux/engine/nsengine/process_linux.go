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
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

type engineProcess struct {
	cmd                                  *exec.Cmd
	done                                 chan struct{}
	err                                  error
	socket, temporary, state, netns, log string
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
	f, err := os.OpenFile(p.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		os.RemoveAll(temp)
		return err
	}
	p.cmd = exec.Command("ip", "netns", "exec", env.Netns, d.exe.Path, "run", "--socket", p.socket, "--state-dir", p.state)
	p.cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(filepath.Dir(env.WorkDir),"inet","probe-ca.pem"))
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
			data,_ := os.ReadFile(p.log)
			if len(data)>4096 {data=data[len(data)-4096:]}
			env.Logf("engine exited: %v\n%s",p.err,data)
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
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", p.netns, d.exe.Path, "cleanup", "--state-dir", p.state)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("engine cleanup: %w: %s", err, out)
	}
	return os.RemoveAll(p.temporary)
}
