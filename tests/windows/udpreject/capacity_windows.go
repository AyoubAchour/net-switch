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
	"slices"
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
	elapsed, sum, err := timedExchange(s, size)
	return float64(elapsed) / float64(time.Millisecond), sum, err
}

// timedExchange measures one echo with the performance counter. A failed
// write reports zero elapsed time, as the old millisecond result did.
func timedExchange(s heldDatagram, size int) (time.Duration, string, error) {
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
	return winclock.Since(started), fmt.Sprintf("%x", sha256.Sum256(buffer[:n])), err
}

// A verify reply carries at most this many failure details; the per-label
// counts still cover every failed echo.
const sweepFailureExamples = 16

type sweepFailure struct {
	Token, Local, Error, NativeError string
	MS                               float64
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
	var code syscall.Errno
	if errors.As(err, &code) {
		return fmt.Sprintf("ERRNO_%d", code)
	}
	return "OTHER"
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
				// StartMS and EndMS bound the whole attempt (open, exchange
				// or failure) on this process's monotonic clock, so a
				// re-attempt can be timed from the original start.
				StartMS, EndMS          float64
				ReplyBytes              int
				FailedAt                time.Time `json:",omitzero"`
				NativeError, NativeCall string    `json:",omitempty"`
				NativeCode              uint32    `json:",omitempty"`
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
						clockMS := func() float64 { return float64(winclock.Now().Microseconds()) / 1000 }
						attempts[i].StartMS = clockMS()
						defer func() { attempts[i].EndMS = clockMS() }()
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
			// One outcome slot per held session. Only exact echoes become
			// latency samples; a failed echo is counted, never a zero sample.
			elapsed := make([]time.Duration, len(held))
			errs := make([]error, len(held))
			started := winclock.Now()
			for base := 0; base < len(held); base += 32 {
				var workers sync.WaitGroup
				for i := base; i < min(base+32, len(held)); i++ {
					workers.Go(func() { elapsed[i], _, errs[i] = timedExchange(held[i], command.Size) })
				}
				workers.Wait()
			}
			sweep := winclock.Since(started)
			var maxMS float64
			samples := make([]int64, 0, len(held))
			labels := map[string]int{}
			examples := []sweepFailure{}
			digest := sha256.New()
			for i, s := range held {
				digest.Write(s.token)
				ms := float64(elapsed[i]) / float64(time.Millisecond)
				maxMS = max(maxMS, ms) // The old field still includes failed echoes.
				if errs[i] == nil {
					// Whole microseconds, rounded up so no echo is understated.
					samples = append(samples, int64((elapsed[i]+time.Microsecond-1)/time.Microsecond))
					continue
				}
				labels[capacityError(errs[i])]++
				if len(examples) < sweepFailureExamples {
					examples = append(examples, sweepFailure{Token: hex.EncodeToString(s.token),
						Local: s.conn.LocalAddr().String(), Error: capacityError(errs[i]), NativeError: errs[i].Error(), MS: ms})
					failure = errors.Join(failure, errs[i])
				}
			}
			if more := len(held) - len(samples) - len(examples); more > 0 {
				failure = errors.Join(failure, fmt.Errorf("%d more held UDP echoes failed", more))
			}
			slices.Sort(samples)
			result["checked"], result["maxMS"] = len(held), maxMS
			result["echoed"], result["samplesUS"] = len(samples), samples
			result["failures"], result["failureExamples"] = labels, examples
			result["heldDigest"] = hex.EncodeToString(digest.Sum(nil))
			result["sweepMS"] = float64(sweep) / float64(time.Millisecond)
		case "release":
			n := min(command.Count, len(held))
			ports := make([]int, 0, n)
			for _, s := range held[:n] {
				ports = append(ports, s.conn.LocalAddr().(*net.UDPAddr).Port)
				failure = errors.Join(failure, s.conn.Close())
			}
			held = held[n:]
			result["released"], result["localPorts"] = n, ports
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
