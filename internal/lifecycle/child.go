package lifecycle

import (
	"io"
	"os/exec"

	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
	"github.com/AyoubAchour/net-switch/internal/service"
)

type adapterChild struct {
	cmd         *exec.Cmd
	out, stderr io.ReadCloser
	release     func()
}

func (p *adapterChild) PID() int          { return p.cmd.Process.Pid }
func (p *adapterChild) Stdout() io.Reader { return p.out }
func (p *adapterChild) Stderr() io.Reader { return p.stderr }
func (p *adapterChild) Kill() error       { return p.cmd.Process.Kill() }
func (p *adapterChild) Wait() error       { defer p.release(); return p.cmd.Wait() }
func startAdapter(exe, config, dir string) (singbox.Child, error) {
	cmd := exec.Command(exe, "run", "-c", config, "--disable-color")
	cmd.Env = service.ChildEnvironment()
	cmd.Dir = dir
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		out.Close()
		return nil, err
	}
	release, err := guardedStart(cmd)
	if err != nil {
		out.Close()
		stderr.Close()
		return nil, err
	}
	return &adapterChild{cmd: cmd, out: out, stderr: stderr, release: release}, nil
}
