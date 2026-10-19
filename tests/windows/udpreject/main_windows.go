//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type sample struct {
	Outcome string  `json:"outcome"`
	Source  string  `json:"source"`
	Sent    int     `json:"sent"`
	MS      float64 `json:"ms"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("Net Switch Windows UDP rejection probe 1")
		return
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		fmt.Fprintln(os.Stderr, "Hosted Windows runners only.")
		os.Exit(1)
	}
	address := flag.String("address", "", "Controlled UDP target")
	count := flag.Int("count", 100, "Concurrent UDP sockets")
	timeout := flag.Duration("timeout", 5*time.Second, "Per-socket refusal deadline")
	flag.Parse()
	if *count < 1 || *count > 100 || *timeout <= 0 || *timeout > 5*time.Second {
		fmt.Fprintln(os.Stderr, "count must be between 1 and 100, timeout between 0 and 5s")
		os.Exit(1)
	}
	peer, err := net.ResolveUDPAddr("udp4", *address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	results, failures := make([]sample, *count), make([]error, *count)
	var work sync.WaitGroup
	for i := range results {
		work.Go(func() { results[i], failures[i] = probe(peer, *timeout) })
	}
	work.Wait()
	if err := errors.Join(failures...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probe(peer *net.UDPAddr, timeout time.Duration) (sample, error) {
	conn, err := net.DialUDP("udp4", nil, peer)
	if err != nil {
		return sample{}, err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return sample{}, err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		// Go disables PORT_UNREACHABLE in netFD.init. Enable it after DialUDP;
		// doing this in Dialer.Control would be overwritten by initialization.
		// https://learn.microsoft.com/windows/win32/winsock/winsock-ioctls
		enabled, returned := uint32(1), uint32(0)
		optionErr = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&enabled)), 4, nil, 0, &returned, nil, 0)
	}); err != nil {
		return sample{}, err
	}
	if optionErr != nil {
		return sample{}, optionErr
	}
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		return sample{}, err
	}
	started, sent := time.Now(), 0
	finish := func(outcome string) (sample, error) {
		return sample{Outcome: outcome, Source: conn.LocalAddr().String(), Sent: sent, MS: float64(time.Since(started).Microseconds()) / 1000}, nil
	}
	reply := make([]byte, 256)
	deadline := started.Add(timeout)
	for time.Now().Before(deadline) {
		sent++
		_, err := conn.Write(payload)
		if err == nil {
			readDeadline := time.Now().Add(25 * time.Millisecond)
			if readDeadline.After(deadline) {
				readDeadline = deadline
			}
			if err = conn.SetReadDeadline(readDeadline); err != nil {
				return sample{}, err
			}
			var n int
			n, err = conn.Read(reply)
			if err == nil {
				if !bytes.Equal(payload, reply[:n]) {
					return sample{}, errors.New("corrupt UDP echo")
				}
				return finish("reply")
			}
		}
		for code, name := range map[windows.Errno]string{
			windows.WSAECONNRESET: "ECONNRESET", windows.WSAECONNREFUSED: "ECONNREFUSED",
			windows.WSAEHOSTUNREACH: "EHOSTUNREACH", windows.WSAENETUNREACH: "ENETUNREACH",
			windows.WSAEACCES: "EACCES",
		} {
			if errors.Is(err, code) {
				return finish(name)
			}
		}
		var networkErr net.Error
		if !errors.As(err, &networkErr) || !networkErr.Timeout() {
			return sample{}, err
		}
	}
	return finish("timeout")
}
