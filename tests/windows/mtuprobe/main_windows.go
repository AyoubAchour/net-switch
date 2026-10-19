//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/windows/socket"
	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("Net Switch controlled MTU probe 1")
		return
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		fmt.Fprintln(os.Stderr, "Hosted Windows runners only.")
		os.Exit(1)
	}
	address := flag.String("address", "", "Controlled UDP target")
	source := flag.String("source", "", "Optional source address")
	index := flag.Int("interface", 0, "Optional interface index")
	size := flag.Int("size", 1200, "UDP payload bytes")
	flag.Parse()
	if err := probe(*address, *source, *index, *size); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probe(address, source string, index, size int) error {
	if size < 1 || size > 8192 {
		return errors.New("payload must be between 1 and 8192 bytes")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	network, level := "udp4", windows.IPPROTO_IP
	if strings.Contains(host, ":") {
		network, level = "udp6", windows.IPPROTO_IPV6
	}
	dialer := net.Dialer{Timeout: 3 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		if index != 0 {
			if err := socket.BindInterface(index)(network, address, raw); err != nil {
				return err
			}
		}
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			// IP_DONTFRAGMENT and IPV6_DONTFRAG are both 14 in ws2ipdef.h.
			optionErr = windows.SetsockoptInt(windows.Handle(fd), level, 14, 1)
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
	if source != "" {
		dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
	}
	conn, err := dialer.DialContext(context.Background(), network, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	started := time.Now()
	finish := func(outcome string) error {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"outcome": outcome, "bytes": size, "ms": time.Since(started).Milliseconds(), "source": conn.LocalAddr().String(), "destination": address, "dontFragment": true})
	}
	reply := make([]byte, 9000)
	for time.Since(started) < 4*time.Second {
		_, err := conn.Write(payload)
		if errors.Is(err, windows.WSAEMSGSIZE) {
			return finish("message-too-large")
		}
		if err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(reply)
		if errors.Is(err, windows.WSAEMSGSIZE) {
			return finish("message-too-large")
		}
		if err == nil {
			if !bytes.Equal(payload, reply[:n]) {
				return errors.New("corrupt UDP echo")
			}
			return finish("reply")
		}
		var networkErr net.Error
		if !errors.As(err, &networkErr) || !networkErr.Timeout() {
			return err
		}
	}
	return finish("timeout")
}
