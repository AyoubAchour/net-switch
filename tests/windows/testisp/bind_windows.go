//go:build windows

package main

import (
	"net"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/windows/socket"
)

func bindInterface(index int) func(string, string, syscall.RawConn) error {
	return socket.BindInterface(index)
}

func boundDialer(index int, source net.IP) *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: source}, Control: bindInterface(index)}
}
