//go:build windows

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type capturedIP struct {
	At  int64  `json:"at"`
	Hex string `json:"hex"`
}
type captureResult struct {
	Source  string       `json:"source"`
	Packets []capturedIP `json:"packets"`
	Seen    int          `json:"seen"`
	Error   string       `json:"error,omitempty"`
}
type ipCapture struct {
	stop, done chan struct{}
	once       sync.Once
	result     captureResult
}

// Test-only, called after the probe's hosted-runner guard. RCVALL_IPLEVEL
// observes the chosen local interface without enabling NIC promiscuous mode.
// Only packets involving the controlled responder are retained, with bounded
// count and header bytes. The probe never injects or alters a packet.
func captureIP(source, remote net.IP) (*ipCapture, error) {
	h, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			windows.Closesocket(h)
		}
	}()
	var address [4]byte
	copy(address[:], source.To4())
	if err := windows.Bind(h, &windows.SockaddrInet4{Addr: address}); err != nil {
		return nil, err
	}
	if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 50); err != nil {
		return nil, err
	}
	level, returned := uint32(3), uint32(0) // RCVALL_IPLEVEL, SIO_RCVALL.
	if err := windows.WSAIoctl(h, 0x98000001, (*byte)(unsafe.Pointer(&level)), 4, nil, 0, &returned, nil, 0); err != nil {
		return nil, err
	}
	c := &ipCapture{stop: make(chan struct{}), done: make(chan struct{}), result: captureResult{Source: source.String()}}
	target := append([]byte(nil), remote.To4()...)
	ok = true
	go func() {
		defer close(c.done)
		defer windows.Closesocket(h)
		recv := windows.NewLazySystemDLL("ws2_32.dll").NewProc("recv")
		b := make([]byte, 65535)
		for {
			select {
			case <-c.stop:
				return
			default:
			}
			n, _, err := recv.Call(uintptr(h), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
			if int32(n) == -1 {
				if errors.Is(err, windows.WSAETIMEDOUT) {
					continue
				}
				c.result.Error = err.Error()
				return
			}
			if n < 20 || n > uintptr(len(b)) || b[0]>>4 != 4 || (b[9] != 1 && b[9] != 17) {
				continue
			}
			if !bytes.Equal(b[12:16], target) && !bytes.Equal(b[16:20], target) {
				continue
			}
			c.result.Seen++
			if len(c.result.Packets) < 512 {
				c.result.Packets = append(c.result.Packets, capturedIP{time.Now().UnixMilli(), hex.EncodeToString(b[:min(int(n), 256)])})
			}
		}
	}()
	return c, nil
}

func (c *ipCapture) finish() captureResult {
	c.once.Do(func() { close(c.stop) })
	<-c.done
	return c.result
}
