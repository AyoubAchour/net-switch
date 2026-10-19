//go:build windows

package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func bindInterface(index int) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			// IP_UNICAST_IF is network byte order, unlike IPV6_UNICAST_IF.
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(index))
			// Winsock IP_UNICAST_IF (ws2ipdef.h); x/sys does not export it.
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(binary.LittleEndian.Uint32(bytes[:])))
		})
		if err != nil {
			return err
		}
		return socketErr
	}
}

func boundDialer(index int, source net.IP) *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: source}, Control: bindInterface(index)}
}
