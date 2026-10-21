//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

type diagQueryTrace struct {
	Stage                                                                    string
	StartedNS, SocketReadyNS, SentNS, ReadStartedNS, CompletedNS, DeadlineNS int64
	Sequence                                                                 uint32
	ReplyReady, ReplyFromKernel, ReplySequenceMatches                        bool
	PeekError                                                                string
}

type diagQueryError struct {
	Trace diagQueryTrace
	cause error
}

func (e *diagQueryError) Error() string {
	return fmt.Sprintf("sock_diag %s: %v (elapsed=%s ready=%t kernel=%t sequence-match=%t peek=%q)", e.Trace.Stage, e.cause,
		time.Duration(e.Trace.CompletedNS-e.Trace.StartedNS), e.Trace.ReplyReady, e.Trace.ReplyFromKernel, e.Trace.ReplySequenceMatches, e.Trace.PeekError)
}
func (e *diagQueryError) Unwrap() error { return e.cause }

// Observe one exact-query response without consuming it or changing a
// deadline. This is failure evidence only; it never changes admission.
func (t *diagQueryTrace) peek(f *os.File) {
	raw, err := f.SyscallConn()
	if err != nil {
		t.PeekError = err.Error()
		return
	}
	var header [16]byte
	var n int
	var peer unix.Sockaddr
	var receiveErr error
	err = raw.Control(func(fd uintptr) {
		n, _, _, peer, receiveErr = unix.Recvmsg(int(fd), header[:], nil, unix.MSG_DONTWAIT|unix.MSG_PEEK)
	})
	if err = errors.Join(err, receiveErr); err != nil {
		t.PeekError = err.Error()
		return
	}
	t.ReplyReady = n >= len(header)
	from, ok := peer.(*unix.SockaddrNetlink)
	t.ReplyFromKernel = ok && from.Pid == 0
	t.ReplySequenceMatches = t.ReplyReady && binary.NativeEndian.Uint32(header[8:12]) == t.Sequence
}

type udpGenerationFailure struct {
	Tuple                              platform.Tuple
	StartedNS, CompletedNS, DeadlineNS int64
	Stage, Error                       string
	Query                              *diagQueryTrace
}

func (o *Owners) recordUDPGenerationFailure(ctx context.Context, tuple platform.Tuple, stage string, started time.Time, err error) {
	f := &udpGenerationFailure{Tuple: tuple, StartedNS: started.UnixNano(), CompletedNS: time.Now().UnixNano(), Stage: stage, Error: err.Error()}
	if deadline, ok := ctx.Deadline(); ok {
		f.DeadlineNS = deadline.UnixNano()
	}
	var query *diagQueryError
	if errors.As(err, &query) {
		trace := query.Trace
		f.Query = &trace
	}
	sequence := o.udpGenerationSequence.Add(1)
	o.udpGenerationFailures[(sequence-1)%uint64(len(o.udpGenerationFailures))].Store(f)
}
