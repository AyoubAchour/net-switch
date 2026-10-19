//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// FDResult is the answer of the modes that connect a socket made elsewhere.
type FDResult struct {
	Seen      string  `json:"seen,omitempty"`
	Err       string  `json:"err,omitempty"`
	ConnectMS float64 `json:"connectMs"`
	Pid       int     `json:"pid"`
	Uid       int     `json:"uid"`
}

func tcpSocket(v6 bool) (int, error) {
	family := syscall.AF_INET
	if v6 {
		family = syscall.AF_INET6
	}
	return syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
}

func sockaddr(ap netip.AddrPort) syscall.Sockaddr {
	if ap.Addr().Is4() {
		return &syscall.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}
	}
	return &syscall.SockaddrInet6{Addr: ap.Addr().As16(), Port: int(ap.Port())}
}

// connectFD connects a blocking TCP socket and reads the whoami answer. It
// takes ownership of fd.
func connectFD(fd int, to netip.AddrPort, timeout time.Duration) FDResult {
	r := FDResult{Pid: os.Getpid(), Uid: os.Getuid()}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
	start := time.Now()
	err := syscall.Connect(fd, sockaddr(to))
	r.ConnectMS = msSince(start)
	if err != nil {
		syscall.Close(fd)
		if err == syscall.EINPROGRESS || err == syscall.EAGAIN {
			r.Err = "TIMEOUT"
		} else {
			r.Err = Code(err)
		}
		return r
	}
	f := os.NewFile(uintptr(fd), "socket")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		r.Err = err.Error()
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(timeout))
	data, err := io.ReadAll(io.LimitReader(conn, 256))
	r.Seen = strings.TrimSpace(string(data))
	if err != nil {
		r.Err = Code(err)
	} else if r.Seen == "" {
		r.Err = "EMPTY"
	}
	return r
}

// presocketConnect creates the socket first, waits, then connects it: the
// socket's cgroup is where the process was when it was created.
func presocketConnect(to netip.AddrPort, wait string, timeout time.Duration) (any, error) {
	fd, err := tcpSocket(to.Addr().Is6())
	if err != nil {
		return nil, err
	}
	if err := waitFile(wait, 60*time.Second); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return connectFD(fd, to, timeout), nil
}

func runConnectFD(args []string) (any, error) {
	fs := flag.NewFlagSet("connect-fd", flag.ContinueOnError)
	fd := fs.Int("fd", 3, "inherited socket")
	to := fs.String("to", "", "whoami server ip:port")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	return connectFD(*fd, list[0], time.Duration(*timeout)*time.Millisecond), nil
}

func runFDPassSend(args []string) (any, error) {
	fs := flag.NewFlagSet("fdpass-send", flag.ContinueOnError)
	path := fs.String("unix", "", "the receiver's socket")
	v6 := fs.Bool("v6", false, "an IPv6 socket")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	fd, err := tcpSocket(*v6)
	if err != nil {
		return nil, err
	}
	var conn *net.UnixConn
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: *path, Net: "unix"})
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			syscall.Close(fd)
			return nil, fmt.Errorf("receiver never listened: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()
	if _, _, err := conn.WriteMsgUnix([]byte("fd"), syscall.UnixRights(fd), nil); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	// From here only the receiver holds the socket.
	syscall.Close(fd)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	reply, _ := io.ReadAll(conn)
	return map[string]any{"sent": true, "reply": strings.TrimSpace(string(reply)), "pid": os.Getpid(), "uid": os.Getuid()}, nil
}

func runFDPassRecv(args []string) (any, error) {
	fs := flag.NewFlagSet("fdpass-recv", flag.ContinueOnError)
	path := fs.String("unix", "", "socket to listen on")
	to := fs.String("to", "", "whoami server ip:port")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(*path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: *path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	if err := os.Chmod(*path, 0o777); err != nil {
		return nil, err
	}
	_ = ln.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.AcceptUnix()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf, oob := make([]byte, 16), make([]byte, syscall.CmsgSpace(4*4))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return nil, fmt.Errorf("no socket arrived: %v", err)
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("no socket arrived: %v", err)
	}
	r := connectFD(fds[0], list[0], time.Duration(*timeout)*time.Millisecond)
	_, _ = conn.Write([]byte("done"))
	return r, nil
}

func runShareExec(args []string) (any, error) {
	fs := flag.NewFlagSet("share-exec", flag.ContinueOnError)
	to := fs.String("to", "", "whoami server ip:port")
	child := fs.String("child", "", "program to start; it's run as <child> app connect-fd --fd 3 --to <to>")
	keep := fs.Bool("keep", true, "keep our copy of the socket open while the child connects")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if *child == "" {
		return nil, usageError{errors.New("--child is required")}
	}
	fd, err := tcpSocket(list[0].Addr().Is6())
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "socket")
	defer f.Close()
	cmd := exec.Command(*child, "app", "connect-fd", "--fd", "3", "--to", list[0].String())
	cmd.ExtraFiles = []*os.File{f}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if !*keep {
		f.Close()
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("child: %w", err)
	}
	return json.RawMessage(bytes.TrimSpace(out.Bytes())), nil
}

func runSpawn(args []string) (any, error) {
	fs := flag.NewFlagSet("spawn", flag.ContinueOnError)
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return nil, usageError{errors.New("usage: spawn -- <program> [args...]")}
	}
	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("child: %w", err)
	}
	return json.RawMessage(bytes.TrimSpace(out)), nil
}
