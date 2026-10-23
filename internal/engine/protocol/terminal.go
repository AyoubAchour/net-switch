package protocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

const TerminalDeliveryTimeout = 2 * time.Second
const TerminalProbeJoinTimeout = time.Second

var ErrNoController = errors.New("no attached controller connection")
var ErrShutdownInProgress = errors.New("explicit stop or lease cleanup already started")

// Terminal is a service-initiated stop, sent only after normal runtime cleanup.
// The controller acknowledges receipt with terminalAck, using this instance,
// epoch and opId. cleanupError covers route cleanup, probe joining and early
// finalization only. Later transport/ownership closes or failures can still
// fail the shutdown: the process exit status, not this record, is authoritative.
// This is independent of the lossy Event stream and carries no restart policy.
// terminalAck is the final receipt; its ordinary reply need not reach the peer
// before shutdown. Controllers must keep reading while sending the receipt.
type Terminal struct {
	Type         string `json:"type"`
	Instance     string `json:"engineInstanceId"`
	Epoch        uint64 `json:"epoch"`
	OpID         string `json:"opId"`
	Reason       string `json:"reason"`
	CleanupError string `json:"cleanupError,omitempty"`
}

type terminalDelivery struct {
	message Terminal
	written chan struct{}
	acked   chan struct{}
	once    sync.Once
}

// StopWithReason fences commands and attachment using the ordinary lease lock,
// cleans up, then waits at most TerminalDeliveryTimeout for terminal delivery.
// Cleanup and delivery errors are separate: an absent or slow controller must
// never prevent fail-open cleanup or turn successful cleanup into a crash.
// The caller keeps transports alive until this returns, then closes/joins them.
// ctx bounds cleanup; the delivery bound starts AFTER cleanup, even if ctx was
// cancelled. No lease clock or renewal semantics are changed.
// ErrShutdownInProgress leaves an earlier explicit stop/lease cleanup in charge;
// no terminal record is sent and this call does not signal Done in that case.
// finalize is optional, belongs to this terminal owner, and runs after Stop and
// probe joining. A probe timeout skips it: the caller must join transports/work
// before finalizing remaining resources. Ownership locks belong to the caller
// until after transport closure, not to finalize.
func (s *Server) StopWithReason(ctx context.Context, reason string, finalize func() error) (cleanupErr, deliveryErr error) {
	s.mu.Lock()
	if s.terminal != nil {
		s.mu.Unlock()
		return errors.New("terminal shutdown already started"), nil
	}
	if s.stopping {
		s.mu.Unlock()
		return nil, ErrShutdownInProgress
	}
	s.stopping = true
	if len(reason) > 4096 {
		reason = reason[:4096]
	}
	var nonce [16]byte
	// crypto/rand.Read either fills the buffer or terminates on entropy failure.
	rand.Read(nonce[:])
	t := &terminalDelivery{message: Terminal{Type: "stopped", Instance: s.Instance, Epoch: s.epoch,
		OpID: hex.EncodeToString(nonce[:]), Reason: reason}, written: make(chan struct{}), acked: make(chan struct{})}
	s.terminal = t
	c := s.controller
	// Cancel probes without closing the transport needed for the receipt.
	for client := range s.clients {
		client.stopWork()
		close(client.terminalStarted)
	}
	var pending []<-chan struct{}
	for _, op := range s.operations {
		select {
		case <-op.done:
		default:
			pending = append(pending, op.done)
		}
	}
	s.mu.Unlock()
	// Restore ordinary routing first. A slow probe must neither delay this
	// nor spend any of the context's cleanup budget before Stop begins.
	cleanupErr = s.runtime.Stop(platform.WithCleanupOwner(ctx))
	join, cancelJoin := context.WithTimeout(context.Background(), TerminalProbeJoinTimeout)
	joined := true
	for _, done := range pending {
		select {
		case <-done:
			continue
		default:
		}
		select {
		case <-done:
		case <-join.Done():
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("probe did not stop before finalization: %w", join.Err()))
			joined = false
		}
		if !joined {
			break
		}
	}
	cancelJoin()
	if joined && finalize != nil {
		cleanupErr = errors.Join(cleanupErr, finalize())
	}
	s.mu.Lock()
	s.stopped = cleanupErr == nil
	if cleanupErr != nil {
		t.message.CleanupError = cleanupErr.Error()
		if len(t.message.CleanupError) > 4096 {
			t.message.CleanupError = t.message.CleanupError[:4096]
		}
	}
	_, connected := s.clients[c]
	if c != nil && connected {
		c.terminal <- t // one terminal record per instance, one reserved slot
	}
	s.mu.Unlock()
	defer s.finish()
	if c == nil || !connected {
		return cleanupErr, ErrNoController
	}
	delivery, cancel := context.WithTimeout(context.Background(), TerminalDeliveryTimeout)
	defer cancel()
	// Closing the transport on timeout unblocks a pending write/reader. Serve
	// owns and joins both, so this does not leave a flush goroutine or handle.
	defer c.cancel()
	for _, done := range []<-chan struct{}{t.written, t.acked} {
		select {
		case <-done:
			continue
		default:
		}
		select {
		case <-done:
		case <-c.done:
			// Serve has joined request workers. An ACK followed immediately
			// by EOF still counts, even if the reader observed EOF first.
			select {
			case <-done:
				continue
			default:
				return cleanupErr, io.ErrClosedPipe
			}
		case <-delivery.Done():
			return cleanupErr, delivery.Err()
		}
	}
	return cleanupErr, nil
}

// Called only with s.mu held. The nonce proves receipt of this terminal record;
// another authenticated connection, old epoch or instance cannot acknowledge it.
func (s *Server) ackTerminal(r Request, c *connection) (any, error) {
	t := s.terminal
	if t == nil || c == nil || c != s.controller || r.Instance != t.message.Instance || r.Epoch != t.message.Epoch || r.OpID != t.message.OpID {
		return nil, errors.New("terminal acknowledgement fenced")
	}
	t.once.Do(func() { close(t.acked) })
	return true, nil
}
