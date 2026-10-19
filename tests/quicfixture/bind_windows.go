//go:build windows

package main

import (
	"strings"
	"syscall"
)

// IP_UNICAST_IF and IPV6_UNICAST_IF (both 31) send through one interface.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
	ipprotoIPv6   = 41
)

func bindInterface(index int) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				sockErr = syscall.SetsockoptInt(syscall.Handle(fd), ipprotoIPv6, ipv6UnicastIf, index)
				return
			}
			// Winsock takes the IPv4 option's index in network byte order.
			be := int(uint32(index)>>24 | uint32(index)>>8&0xff00 | uint32(index)<<8&0xff0000 | uint32(index)<<24)
			sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, be)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
