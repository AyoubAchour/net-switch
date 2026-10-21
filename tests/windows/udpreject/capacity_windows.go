//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

type capacityCommand struct {
	ID      int    `json:"id"`
	Command string `json:"command"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Count   int    `json:"count"`
	App     int    `json:"app"`
	Size    int    `json:"size"`
}

type heldDatagram struct {
	conn  *net.UDPConn
	token []byte
}

func enableUDPRefusal(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		enabled, returned := uint32(1), uint32(0)
		optionErr = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&enabled)), 4, nil, 0, &returned, nil, 0)
	})
	return errors.Join(err, optionErr)
}

func datagramExchange(s heldDatagram, size int) (float64, string, error) {
	request := append([]byte("NSUDPCAP"), s.token...)
	expected := request
	if size != 0 {
		request = binary.BigEndian.AppendUint16(request, uint16(size))
		expected = make([]byte, size)
		for i := range expected {
			expected[i] = byte(i*37+11) ^ s.token[i%8]
		}
	}
	started := winclock.Now()
	s.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := s.conn.Write(request); err != nil {
		return 0, "", err
	}
	buffer := make([]byte, 65536)
	n, err := s.conn.Read(buffer)
	if err == nil && !bytes.Equal(expected, buffer[:n]) {
		err = errors.New("UDP capacity payload mismatch")
	}
	return float64(winclock.Since(started)) / float64(time.Millisecond), fmt.Sprintf("%x", sha256.Sum256(buffer[:n])), err
}

func capacityError(err error) string {
	for code, label := range map[windows.Errno]string{
		windows.WSAENOBUFS: "ENOBUFS", windows.WSAEADDRINUSE: "EADDRINUSE",
		windows.WSAECONNRESET: "ECONNRESET", windows.WSAECONNREFUSED: "ECONNREFUSED",
	} {
		if errors.Is(err, code) {
			return label
		}
	}
	var timed net.Error
	if errors.As(err, &timed) && timed.Timeout() {
		return "TIMEOUT"
	}
	return err.Error()
}

// The host sends commands on stdin and receives one JSON reply per command.
// Held sockets have no receive goroutine; each command uses at most 32 workers.
func capacityProbe() error {
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var held []heldDatagram
	serial := uint32(0)
	defer func() {
		for _, s := range held {
			s.conn.Close()
		}
	}()
	for {
		var command capacityCommand
		if err := decoder.Decode(&command); err != nil {
			return err
		}
		result := map[string]any{}
		var failure error
		switch command.Command {
		case "open":
			if command.Count < 1 || command.Count > 4096 || command.App < 1 {
				failure = errors.New("bad UDP capacity count or app")
				break
			}
			address := net.ParseIP(command.Host)
			network := "udp4"
			if address.To4() == nil {
				network = "udp6"
			}
			peer := &net.UDPAddr{IP: address, Port: command.Port}
			type attempt struct {
				Token, Local, Remote, SHA256, Error string
				MS                                  float64
				ReplyBytes                          int
				FailedAt                            time.Time `json:",omitzero"`
				NativeError, NativeCall             string    `json:",omitempty"`
				NativeCode                          uint32    `json:",omitempty"`
			}
			attempts := make([]attempt, command.Count)
			sockets := make([]heldDatagram, command.Count)
			for base := 0; base < command.Count; base += 32 {
				var workers sync.WaitGroup
				for i := base; i < min(base+32, command.Count); i++ {
					serial++
					token := make([]byte, 8)
					binary.BigEndian.PutUint32(token, uint32(command.App))
					binary.BigEndian.PutUint32(token[4:], serial)
					attempts[i].Token = hex.EncodeToString(token)
					workers.Go(func() {
						conn, err := net.DialUDP(network, nil, peer)
						if err == nil {
							err = enableUDPRefusal(conn)
						}
						if err == nil {
							attempts[i].Local = conn.LocalAddr().String()
							attempts[i].Remote = conn.RemoteAddr().String()
							attempts[i].ReplyBytes = command.Size
							if command.Size == 0 {
								attempts[i].ReplyBytes = 16
							}
							s := heldDatagram{conn: conn, token: token}
							attempts[i].MS, attempts[i].SHA256, err = datagramExchange(s, command.Size)
							if err == nil {
								sockets[i] = s
								return
							}
						}
						if conn != nil {
							conn.Close()
						}
						attempts[i].Error = capacityError(err)
						attempts[i].FailedAt = time.Now()
						attempts[i].NativeError = err.Error()
						var code syscall.Errno
						if errors.As(err, &code) {
							attempts[i].NativeCode = uint32(code)
						}
						var call *os.SyscallError
						if errors.As(err, &call) {
							attempts[i].NativeCall = call.Syscall
						}
					})
				}
				workers.Wait()
			}
			for _, s := range sockets {
				if s.conn != nil {
					held = append(held, s)
				}
			}
			result["attempts"] = attempts
		case "verify":
			var maxMS float64
			for base := 0; base < len(held); base += 32 {
				var workers sync.WaitGroup
				var mu sync.Mutex
				for _, s := range held[base:min(base+32, len(held))] {
					workers.Go(func() {
						ms, _, err := datagramExchange(s, command.Size)
						mu.Lock()
						maxMS = max(maxMS, ms)
						failure = errors.Join(failure, err)
						mu.Unlock()
					})
				}
				workers.Wait()
			}
			result["checked"], result["maxMS"] = len(held), maxMS
		case "release":
			n := min(command.Count, len(held))
			for _, s := range held[:n] {
				failure = errors.Join(failure, s.conn.Close())
			}
			held = held[n:]
			result["released"] = n
		case "status":
		case "close":
			for _, s := range held {
				failure = errors.Join(failure, s.conn.Close())
			}
			held = nil
		default:
			failure = fmt.Errorf("unknown capacity command %q", command.Command)
		}
		result["held"] = len(held)
		reply := map[string]any{"id": command.ID, "result": result}
		if failure != nil {
			reply["error"] = failure.Error()
		}
		if err := encoder.Encode(reply); err != nil {
			return err
		}
		if command.Command == "close" {
			return failure
		}
	}
}
