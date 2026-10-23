package lifecycle

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
)

type nativeForwardingHealth struct {
	socket   *net.UDPConn
	index    int
	port     uint16
	success  uint64
	channel  *nativeHostChannel
	key      [32]byte
	serial   uint64
	state    string
	since    time.Time
	now      func() time.Time
	failures uint64
	started  int64
	epoch    uint64
}

func (h *nativeForwardingHealth) target(state supervisor.Message, bind func(int, uint16) error) error {
	if h.index == state.Index && h.port == state.Port && h.started == state.Started && h.epoch == state.Epoch {
		return nil
	}
	if err := bind(state.Index, state.Port); err != nil {
		return err
	}
	h.index, h.port, h.started, h.epoch = state.Index, state.Port, state.Started, state.Epoch
	return nil
}

// Registrar startup alone may consume 15 s. Routing startup gets another
// 20 s for setup/rollback; stopping has its own 20 s grace, never a health
// verdict. The host then uses the verified termination and cleanup budget.
const nativeStartBound = 35 * time.Second
const nativeStopBound = 20 * time.Second

type nativeTransitionTimeout struct{ state string }

func (e *nativeTransitionTimeout) Error() string {
	return "native lifecycle deadline exceeded: " + e.state
}
func (h *nativeForwardingHealth) lifecycle(state string, now time.Time) error {
	if h.state != state {
		h.state, h.since = state, now
	}
	bound := time.Duration(0)
	switch state {
	case "starting":
		bound = nativeStartBound
	case "stopping":
		bound = nativeStopBound
	case "error":
		bound = 30 * time.Second // Control recovery or lease-driven exit
	case "off", "on":
	default:
		return fmt.Errorf("unknown native lifecycle state %q", state)
	}
	if bound != 0 && now.Sub(h.since) >= bound {
		return &nativeTransitionTimeout{state}
	}
	return nil
}

func (h *nativeForwardingHealth) Health(ctx context.Context) (result error) {
	defer func() {
		if result != nil {
			h.failures++
		}
	}()
	state, err := h.channel.status(ctx)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := nativeAwake
	if h.now != nil {
		now = h.now
	}
	effective := state.State
	if effective == "on" && (state.Index <= 0 || state.Port == 0) {
		effective = "starting"
	}
	if err := h.lifecycle(effective, now()); err != nil {
		return err
	}
	if effective != "on" {
		h.index, h.port = 0, 0
		return nil
	} // no capture or forwarding to exercise
	if err := h.target(state, func(index int, port uint16) error {
		raw, err := h.socket.SyscallConn()
		if err != nil {
			return err
		}
		if err := bindHealthSocket(raw, index); err != nil {
			return err
		}
		return connectHealthSocket(raw, port)
	}); err != nil {
		return err
	}
	sock := h.socket
	if deadline, ok := ctx.Deadline(); ok {
		sock.SetDeadline(deadline)
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { sock.SetDeadline(time.Now()); close(finished) })
	defer func() {
		if !stop() {
			<-finished
		}
	}()
	var request [40]byte
	copy(request[:32], h.key[:])
	h.serial++
	binary.BigEndian.PutUint64(request[32:], h.serial)
	if _, err := sock.Write(request[:]); err != nil {
		return err
	}
	var response [41]byte
	for range 16 {
		n, from, err := sock.ReadFrom(response[:])
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if from.String() == net.JoinHostPort("198.18.0.2", strconv.Itoa(int(state.Port))) && bytes.Equal(response[:n], request[:]) {
			h.success++
			return nil
		}
	}
	return errors.New("private forwarding stale/mismatched response bound exceeded")
}
