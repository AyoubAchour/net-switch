//go:build windows

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func streamProbe(peer *net.UDPAddr, port int, duration time.Duration, token string, capture bool) error {
	if port < 1024 || port > 65535 || duration < time.Second || duration > 10*time.Second {
		return errors.New("invalid identity stream limits")
	}
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 16 {
		return errors.New("identity token must be 16 random bytes")
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{Port: port}, peer)
	if err != nil {
		return err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		on, returned := uint32(1), uint32(0)
		optionErr = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&on)), 4, nil, 0, &returned, nil, 0)
	})
	if err != nil || optionErr != nil {
		return errors.Join(err, optionErr)
	}
	type event struct {
		At      int64  `json:"at"`
		Outcome string `json:"outcome"`
	}
	result := struct {
		StartedAt int64          `json:"startedAt"`
		Source    string         `json:"source"`
		Token     string         `json:"token"`
		Sent      int            `json:"sent"`
		Events    []event        `json:"events"`
		Capture   *captureResult `json:"capture,omitempty"`
	}{StartedAt: time.Now().UnixMilli(), Source: conn.LocalAddr().String(), Token: token}
	var observer *ipCapture
	if capture {
		observer, err = captureIP(conn.LocalAddr().(*net.UDPAddr).IP, peer.IP)
		if err != nil {
			result.Capture = &captureResult{Error: err.Error()}
		} else {
			defer observer.finish()
		}
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	deadline := time.Now().Add(duration)
	var reply [128]byte
	for time.Now().Before(deadline) {
		payload := []byte(fmt.Sprintf("NS-ID:%s:%08d", token, result.Sent))
		result.Sent++
		_, err := conn.Write(payload)
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			var n int
			n, err = conn.Read(reply[:])
			if err == nil {
				// A late reply belongs to this stream only if its token agrees.
				if n < 38 || !bytes.Equal(reply[:38], payload[:38]) {
					return errors.New("foreign stream data returned")
				}
				result.Events = append(result.Events, event{time.Now().UnixMilli(), "reply"})
			}
		}
		if err != nil {
			var n net.Error
			if errors.As(err, &n) && n.Timeout() {
				result.Events = append(result.Events, event{time.Now().UnixMilli(), "timeout"})
			} else if errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNREFUSED) {
				result.Events = append(result.Events, event{time.Now().UnixMilli(), "refused"})
			} else {
				return err
			}
		}
		<-tick.C
	}
	if observer != nil {
		captured := observer.finish()
		result.Capture = &captured
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
