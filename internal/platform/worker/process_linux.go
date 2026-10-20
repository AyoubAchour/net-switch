package worker

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

type linuxProcess struct {
	cmd         *exec.Cmd
	in          io.WriteCloser
	out, stderr io.ReadCloser
	once        sync.Once
	err         error
}

func Start(executable string, args []string) (Process, error) {
	if !filepath.IsAbs(executable) || len(args) < 2 || args[0] != "worker" {
		return nil, fmt.Errorf("worker launcher requires its executable and worker mode")
	}
	cmd := exec.Command(executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	p := &linuxProcess{cmd: cmd}
	var err error
	if p.in, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if p.out, err = cmd.StdoutPipe(); err != nil {
		p.in.Close()
		return nil, err
	}
	if p.stderr, err = cmd.StderrPipe(); err != nil {
		p.in.Close()
		p.out.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		p.in.Close()
		p.out.Close()
		p.stderr.Close()
		return nil, err
	}
	return p, nil
}
func (p *linuxProcess) Input() io.WriteCloser { return p.in }
func (p *linuxProcess) Output() io.ReadCloser { return p.out }
func (p *linuxProcess) Errors() io.ReadCloser { return p.stderr }
func (p *linuxProcess) Wait() error           { p.once.Do(func() { p.err = p.cmd.Wait() }); return p.err }
func (p *linuxProcess) Kill() error {
	err := p.cmd.Process.Kill()
	if err == os.ErrProcessDone {
		return nil
	}
	return err
}
func (p *linuxProcess) Close() error {
	_ = p.Kill()
	_ = p.Wait()
	p.in.Close()
	p.out.Close()
	return p.stderr.Close()
}
