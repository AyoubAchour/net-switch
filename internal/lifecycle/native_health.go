package lifecycle

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

type nativeForwardingHealth struct {
	socket  *net.UDPConn
	index   int
	port    uint16
	success uint64
	channel *nativeHostChannel
	key     [32]byte
	serial  uint64
}

func (h *nativeForwardingHealth) Health(ctx context.Context) error {
	state, err := h.channel.status(ctx)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if state.State == "off" {
		return nil
	} // no capture or forwarding to exercise
	if state.State != "on" || state.Index <= 0 || state.Port == 0 {
		return errors.New("native forwarding is not ready")
	}
	if h.index == 0 {
		raw, err := h.socket.SyscallConn()
		if err != nil {
			return err
		}
		if err := bindHealthSocket(raw, state.Index); err != nil {
			return err
		}
		if err := connectHealthSocket(raw, state.Port); err != nil {
			return err
		}
		h.index, h.port = state.Index, state.Port
	}
	if h.index != state.Index || h.port != state.Port {
		return errors.New("forwarding identity changed within child lifetime")
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
