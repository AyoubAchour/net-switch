//go:build windows

package winengine

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

// shutdownTail is the resource boundary used by Serve after accepting clients.
// finalize closes probe-dependent resources; release relinquishes ownership
// and state exclusion only after every transport and service worker has joined.
type shutdownTail struct {
	runtime   protocol.Runtime
	server    *protocol.Server
	loss      *adapterLoss
	fatal     <-chan error
	cancel    func()
	closePipe func() error
	join      func()
	finalize  func() error // idempotent, including its returned error
	release   func() error
}

func joinShutdownError(err, next error) error {
	if next == nil {
		return err // preserve a direct completed exit outcome
	}
	return errors.Join(err, next)
}

func (s shutdownTail) takeFatal() error {
	select {
	case err := <-s.fatal:
		return err
	default:
		return nil
	}
}

func serveUntilStopped(parent context.Context, s shutdownTail) (err error) {
	select {
	case <-parent.Done():
	case <-s.server.Done():
	case <-s.loss.ready:
	case err = <-s.fatal:
	}
	// Decide from the latch, not the random winner of the wakeup select. A
	// queued generic failure must accompany a loss rather than hide its reason.
	lost := s.loss.cause.Load()
	if parent.Err() != nil {
		lost = nil
	}
	err = joinShutdownError(err, s.takeFatal())
	if lost == nil && err != nil {
		log.Printf("routing stopped, restoring normal routes: %v", err)
	}
	stop, cancelStop := context.WithTimeout(context.Background(), 15*time.Second)
	terminalOwned := false
	finalized := false
	if lost != nil {
		log.Printf("%s; restoring normal routes: %v", AdapterLostReason, lost.Cause)
		prior := err
		cleanup, delivery := s.server.StopWithReason(stop, AdapterLostReason, func() error {
			finalized = true
			return errors.Join(prior, s.finalize(), s.takeFatal())
		})
		if errors.Is(delivery, protocol.ErrShutdownInProgress) {
			// Explicit stop/lease already owns the fence. Preserve retry and
			// its reply-before-close rule, without running terminal finalizers.
			cancelStop()
			stop, cancelStop = context.WithTimeout(context.Background(), 15*time.Second)
			err = joinShutdownError(err, s.runtime.Stop(stop))
			deliveryCtx, cancelDelivery := context.WithTimeout(context.Background(), protocol.TerminalDeliveryTimeout)
			select {
			case <-s.server.Done():
			case <-deliveryCtx.Done():
			}
			cancelDelivery()
		} else {
			terminalOwned = true
			if finalized {
				// The callback already included prior failures and finalization.
				err = cleanup
			} else {
				err = joinShutdownError(err, cleanup)
			}
			if delivery != nil {
				log.Printf("adapter lost terminal delivery: %v", delivery)
			}
		}
	} else {
		err = joinShutdownError(err, s.runtime.Stop(stop))
	}
	cancelStop()
	s.cancel()
	err = joinShutdownError(err, s.closePipe())
	s.join()
	// If a probe exceeded the terminal join bound, it prevented early
	// finalization. Joining transports above makes this final attempt safe.
	if !finalized {
		err = joinShutdownError(err, s.finalize())
	}
	err = joinShutdownError(err, s.release())
	err = joinShutdownError(err, s.takeFatal())
	if terminalOwned {
		return adapterLossResult(lost.Cause, err)
	}
	return err
}
