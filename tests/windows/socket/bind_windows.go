//go:build windows

// Package socket contains explicit interface binding for the runner harnesses.
package socket

import (
	"encoding/binary"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func BindInterface(index int) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, index)
				return
			}
			// Winsock IP_UNICAST_IF is network byte order, unlike IPv6's option.
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(index))
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(binary.LittleEndian.Uint32(bytes[:])))
		})
		if err != nil {
			return err
		}
		return socketErr
	}
}
