//go:build windows

package winchild

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// Registrar is sent only over the authenticated private child channel while
// the registrar is suspended. The child keeps this handle open until the ACK.
type Registrar struct {
	Handle uint64
	PID    uint32
}

var compareProcessObjects = windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles")

// TrackRegistrar duplicates the capability out of the verified child, checks
// its process identity, then retains SYNCHRONIZE only. No registrar job handle
// is duplicated: the child remains its sole lifetime owner. ACK must precede
// registrar resume, so a missing ACK cannot leave a live unobserved registration.
func (p *Process) TrackRegistrar(r Registrar) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return os.ErrClosed
	}
	select {
	case <-p.done:
		return errors.New("registrar from exited child")
	default:
	}
	if r.Handle == 0 || r.PID == 0 || r.PID == p.Identity.PID {
		return errors.New("invalid registrar capability")
	}
	kept := p.registrars[:0]
	var closeErr error
	for _, h := range p.registrars {
		state, err := windows.WaitForSingleObject(h.Handle("prune exited registrar"), 0)
		if err == nil && state == windows.WAIT_OBJECT_0 {
			closeErr = errors.Join(closeErr, closeOwner(h, "pruned registrar close"))
		} else {
			kept = append(kept, h)
		}
	}
	p.registrars = kept
	if closeErr != nil {
		return closeErr
	}
	var inspected windows.Handle
	if err := windows.DuplicateHandle(p.process.Handle("registrar capability source"), windows.Handle(r.Handle), windows.CurrentProcess(), &inspected,
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, 0); err != nil {
		return err
	}
	inspection := winhandle.Open(inspected, "registrar identity observer")
	pid, err := windows.GetProcessId(inspected)
	if err != nil || pid != r.PID {
		return errors.Join(fmt.Errorf("registrar capability identity mismatch: got=%d want=%d error=%v", pid, r.PID, err), closeOwner(inspection, "registrar identity close"))
	}
	if err := compareProcessObjects.Find(); err != nil {
		return errors.Join(err, closeOwner(inspection, "registrar identity close"))
	}
	for _, existing := range p.registrars {
		if same, _, _ := compareProcessObjects.Call(uintptr(inspected), uintptr(existing.Handle("registrar acknowledgement retry"))); same != 0 {
			return closeOwner(inspection, "repeated registrar identity close")
		}
	}
	if len(kept) >= 4 {
		return errors.Join(errors.New("registrar observer capacity exhausted"), closeOwner(inspection, "excess registrar identity close"))
	}
	var observed windows.Handle
	err = windows.DuplicateHandle(windows.CurrentProcess(), inspected, windows.CurrentProcess(), &observed, windows.SYNCHRONIZE, false, 0)
	closeErr = closeOwner(inspection, "registrar identity close")
	if err != nil {
		return errors.Join(err, closeErr)
	}
	owner := winhandle.Open(observed, "registrar synchronize observer")
	if closeErr != nil {
		return errors.Join(closeErr, closeOwner(owner, "failed registrar observer close"))
	}
	p.registrars = append(p.registrars, owner)
	return nil
}

func (p *Process) joinRegistrars(ctx context.Context) error {
	p.joinMu.Lock()
	defer p.joinMu.Unlock()
	p.mu.Lock()
	if p.registrarsJoined {
		p.mu.Unlock()
		return nil
	}
	// Child exit fences TrackRegistrar; no registrations can be added now.
	registrars := append([]winhandle.Owner(nil), p.registrars...)
	p.mu.Unlock()
	for _, registrar := range registrars {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			state, err := windows.WaitForSingleObject(registrar.Handle("supervisor registrar join"), 25)
			if err != nil {
				return err
			}
			if state == windows.WAIT_OBJECT_0 {
				break
			}
			if state != uint32(windows.WAIT_TIMEOUT) {
				return fmt.Errorf("unexpected registrar wait result %d", state)
			}
		}
	}
	p.mu.Lock()
	p.registrarsJoined = true
	p.mu.Unlock()
	return nil
}
