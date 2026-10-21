//go:build linux

package linux

import (
	"errors"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

// sendScript replays send results and error-queue evidence in order, and
// records how sendDatagram used them.
type sendScript struct {
	sends    []error
	passes   []errorEvidence
	calls    int
	explains []unix.Errno
	clears   int
}

func (s *sendScript) run(t *testing.T) error {
	t.Helper()
	return sendDatagram(func() error {
		s.calls++
		if s.calls > len(s.sends) {
			t.Fatalf("send %d was not scripted: the retry is unbounded", s.calls)
		}
		return s.sends[s.calls-1]
	}, func(errno unix.Errno) errorEvidence {
		s.explains = append(s.explains, errno)
		if len(s.explains) > len(s.passes) {
			t.Fatalf("error-queue pass %d was not scripted", len(s.explains))
		}
		return s.passes[len(s.explains)-1]
	}, func() { s.clears++ })
}

func TestUDPSendRetriesPreviousDestinationErrorOnce(t *testing.T) {
	s := sendScript{sends: []error{unix.ECONNREFUSED, nil}, passes: []errorEvidence{{empty: true, remote: true}}}
	if err := s.run(t); err != nil || s.calls != 2 || len(s.explains) != 1 || s.clears != 1 {
		t.Fatalf("send B after error A: calls=%d passes=%d clears=%d err=%v", s.calls, len(s.explains), s.clears, err)
	}
	// Port unreachable only comes from ICMP, so a second one is another
	// destination's report too, never B's.
	s = sendScript{sends: []error{unix.ECONNREFUSED, unix.ECONNREFUSED}, passes: []errorEvidence{{empty: true, remote: true}}}
	if err := s.run(t); !errors.Is(err, platform.ErrDatagramDropped) || s.calls != 2 || len(s.explains) != 1 {
		t.Fatalf("retry was unbounded or falsely attributed: calls=%d passes=%d err=%v", s.calls, len(s.explains), err)
	}
}

func TestUDPNoBuffersIsCountableSilentDrop(t *testing.T) {
	s := sendScript{sends: []error{unix.ENOBUFS}}
	if err := s.run(t); !errors.Is(err, platform.ErrDatagramDropped) || s.calls != 1 || len(s.explains) != 0 || s.clears != 0 {
		t.Fatalf("ENOBUFS became unreachable, was retried or drained remote errors: %v", err)
	}
	// After another destination's error is consumed, a full send buffer is
	// still a local drop.
	s = sendScript{sends: []error{unix.EHOSTUNREACH, unix.ENOBUFS}, passes: []errorEvidence{{empty: true, remote: true}}}
	if err := s.run(t); !errors.Is(err, platform.ErrDatagramDropped) || s.calls != 2 {
		t.Fatalf("ENOBUFS on the retry was not a counted drop: %v", err)
	}
}

// Every errno Linux 6.8's UDPv4/v6 ICMP handlers latch must be recovered
// from, not only port unreachable.
func TestUDPSendRecoversEveryLatchedICMPErrno(t *testing.T) {
	for _, errno := range []unix.Errno{
		unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EPROTO, unix.EMSGSIZE,
		unix.EACCES, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EHOSTDOWN, unix.ENONET,
	} {
		s := sendScript{sends: []error{errno, nil}, passes: []errorEvidence{{empty: true, remote: true}}}
		if err := s.run(t); err != nil || s.calls != 2 || s.clears != 1 || s.explains[0] != errno {
			t.Fatalf("%v from another destination lost B's datagram: calls=%d clears=%d err=%v", errno, s.calls, s.clears, err)
		}
	}
}

func TestUDPSendSeparatesLocalAndRemoteTooBig(t *testing.T) {
	// A synchronous local EMSGSIZE queues a LOCAL report naming this
	// destination. It is this send's own result, so it is not retried.
	s := sendScript{sends: []error{unix.EMSGSIZE}, passes: []errorEvidence{{empty: true, local: true, mtu: 1280}}}
	err := s.run(t)
	var big *platform.TooBig
	if !errors.As(err, &big) || big.MTU != 1280 || s.calls != 1 || s.clears != 0 {
		t.Fatalf("local too big was not reported for its own destination: calls=%d err=%v", s.calls, err)
	}
	// A remote Packet Too Big for A only latched EMSGSIZE. B's datagram fits
	// and must be sent.
	s = sendScript{sends: []error{unix.EMSGSIZE, nil}, passes: []errorEvidence{{empty: true, remote: true}}}
	if err := s.run(t); err != nil || s.calls != 2 {
		t.Fatalf("A's Packet Too Big became B's: %v", err)
	}
	// A's remote report came first, and B's datagram is too big locally as
	// well. The retry's LOCAL report gives B its own MTU.
	s = sendScript{sends: []error{unix.EMSGSIZE, unix.EMSGSIZE}, passes: []errorEvidence{{empty: true, remote: true}, {empty: true, local: true, mtu: 1400}}}
	if err := s.run(t); !errors.As(err, &big) || big.MTU != 1400 || len(s.explains) != 2 {
		t.Fatalf("B's local too big after A's remote one: %v", err)
	}
	// An unrelated queued error does not turn B's local failure into a drop:
	// another destination's port unreachable latched first.
	s = sendScript{sends: []error{unix.ECONNREFUSED, unix.EMSGSIZE}, passes: []errorEvidence{{empty: true, remote: true}, {empty: true, local: true, mtu: 1280}}}
	if err := s.run(t); !errors.As(err, &big) || big.MTU != 1280 {
		t.Fatalf("queued error reclassified a local too big: %v", err)
	}
	// A second EMSGSIZE with no LOCAL report is another remote report that
	// latched during the retry. Never fabricate B's Packet Too Big.
	for _, second := range []errorEvidence{{empty: true, remote: true}, {empty: true}} {
		s = sendScript{sends: []error{unix.EMSGSIZE, unix.EMSGSIZE}, passes: []errorEvidence{{empty: true, remote: true}, second}}
		if err := s.run(t); !errors.Is(err, platform.ErrDatagramDropped) {
			t.Fatalf("unproven EMSGSIZE was attributed to B (%+v): %v", second, err)
		}
	}
}

func TestUDPSendSecondAsyncErrorIsCountedDrop(t *testing.T) {
	// A matching ICMP report arrived during the retry: the second failure is
	// not B's.
	s := sendScript{sends: []error{unix.EHOSTUNREACH, unix.EHOSTUNREACH}, passes: []errorEvidence{{empty: true, remote: true}, {empty: true, remote: true}}}
	if err := s.run(t); !errors.Is(err, platform.ErrDatagramDropped) || s.calls != 2 {
		t.Fatalf("second async error fabricated B's unreachable: %v", err)
	}
	// More than one pass of reports was queued: a report latched during the
	// retry would be out of sight, so the bounded pass cannot prove anything.
	for _, errno := range []unix.Errno{unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EACCES, unix.EMSGSIZE, unix.EPROTO} {
		s = sendScript{sends: []error{errno, errno}, passes: []errorEvidence{{remote: true}}}
		if err := s.run(t); !errors.Is(err, platform.ErrDatagramDropped) || s.calls != 2 || len(s.explains) != 1 {
			t.Fatalf("%v behind a full error queue was attributed to B or explored unboundedly: %v", errno, err)
		}
	}
}

func TestUDPSendKeepsSynchronousRouteFailures(t *testing.T) {
	// No queued report and no new one: Linux's route lookup failed for this
	// destination, so the NAT should answer it.
	for _, errno := range []unix.Errno{unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EACCES} {
		s := sendScript{sends: []error{errno, errno}, passes: []errorEvidence{{empty: true}, {empty: true}}}
		if err := s.run(t); !errors.Is(err, errno) || s.calls != 2 || len(s.explains) != 2 {
			t.Fatalf("synchronous %v was hidden: calls=%d err=%v", errno, s.calls, err)
		}
	}
	// A different matching report in the queue does not hide it either.
	s := sendScript{sends: []error{unix.EHOSTUNREACH, unix.EHOSTUNREACH}, passes: []errorEvidence{{empty: true, remote: true}, {empty: true}}}
	if err := s.run(t); !errors.Is(err, unix.EHOSTUNREACH) {
		t.Fatalf("drained report hid B's synchronous route failure: %v", err)
	}
	// Errors Linux never latches from ICMP are returned untouched.
	s = sendScript{sends: []error{unix.EPERM}}
	if err := s.run(t); !errors.Is(err, unix.EPERM) || s.calls != 1 || len(s.explains) != 0 {
		t.Fatalf("local error was retried or drained: %v", err)
	}
	s = sendScript{sends: []error{unix.ECONNREFUSED, unix.EAGAIN}, passes: []errorEvidence{{empty: true, remote: true}}}
	if err := s.run(t); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("full send buffer on the retry was not would-block: %v", err)
	}
}
