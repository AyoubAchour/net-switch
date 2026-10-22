//go:build windows

package winengine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	winplatform "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const ownershipPreparationNamespace = "NetSwitchEngineOwnershipPreparationV1"

// Namespace aliases belong to a process. Keep their open/close lifetimes from
// overlapping locally; the namespace mutex serializes different processes.
var ownershipPreparationGate = make(chan struct{}, 1)

func ownershipDirectory(ctx context.Context, path string) (*winhandle.File, error) {
	var directory *winhandle.File
	err := withOwnershipPreparation(ctx, func() error {
		if _, err := winplatform.PrepareMachineDirectory(path); err != nil {
			return fmt.Errorf("prepare engine ownership directory: %w", err)
		}
		// The protected HKLM record, not a locally chosen candidate, decides
		// where every startup and recovery takes its lifetime byte lock.
		resolved, err := winplatform.ResolveMachineDirectory(path)
		if err != nil {
			return fmt.Errorf("resolve engine ownership directory: %w", err)
		}
		directory, err = openStateDirectory(resolved)
		return err
	})
	if err != nil && directory != nil {
		err = errors.Join(err, directory.Close())
		directory = nil
	}
	return directory, err
}

func withOwnershipPreparation(ctx context.Context, prepare func() error) (err error) {
	select {
	case ownershipPreparationGate <- struct{}{}:
		defer func() { <-ownershipPreparationGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	namespace, err := openOwnershipNamespace(ctx)
	if err != nil {
		return fmt.Errorf("open ownership preparation namespace: %w", err)
	}
	defer func() {
		closeErr := namespace.Close("ownership namespace close", func(h windows.Handle) error {
			// Never DESTROY: that would unlink the shared namespace while
			// another process still has a waiter inside it.
			ok, _, e := windows.NewLazySystemDLL("kernel32.dll").NewProc("ClosePrivateNamespace").Call(uintptr(h), 0)
			if ok == 0 {
				return e
			}
			return nil
		})
		err = errors.Join(err, closeErr)
	}()
	name, _ := windows.UTF16PtrFromString(ownershipPreparationNamespace + `\prepare`)
	sa, err := security(privateSDDL)
	if err != nil {
		return err
	}
	h, err := windows.CreateMutex(sa, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("open ownership preparation mutex: %w", err)
	}
	mutex := winhandle.Open(h, "ownership preparation mutex open")
	defer func() { err = errors.Join(err, mutex.HandleClose("ownership preparation mutex close")) }()
	// Windows mutex ownership belongs to an OS thread, including abandoned
	// mutex acquisition. Keep preparation and ReleaseMutex on that thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := waitOwnershipPreparation(ctx, func() (uint32, error) {
		return windows.WaitForSingleObject(mutex.Handle("ownership preparation wait"), 0)
	}); err != nil {
		return fmt.Errorf("wait for ownership directory preparation: %w", err)
	}
	defer func() { err = errors.Join(err, windows.ReleaseMutex(mutex.Handle("ownership preparation release"))) }()
	return prepare()
}

func openOwnershipNamespace(ctx context.Context) (winhandle.Owner, error) {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	name, _ := windows.UTF16PtrFromString(ownershipPreparationNamespace)
	boundary, _, err := kernel.NewProc("CreateBoundaryDescriptorW").Call(uintptr(unsafe.Pointer(name)), 0)
	if boundary == 0 {
		return winhandle.Owner{}, err
	}
	defer func() { kernel.NewProc("DeleteBoundaryDescriptor").Call(boundary) }()
	admin, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return winhandle.Owner{}, err
	}
	// No session SID: elevated installers, standalone engines and SYSTEM
	// recovery share the same namespace across logon sessions. An unelevated
	// token cannot create this boundary, even before the first engine start.
	ok, _, err := kernel.NewProc("AddSIDToBoundaryDescriptor").Call(uintptr(unsafe.Pointer(&boundary)), uintptr(unsafe.Pointer(admin)))
	if ok == 0 {
		return winhandle.Owner{}, err
	}
	sa, err := security(privateSDDL)
	if err != nil {
		return winhandle.Owner{}, err
	}
	h, err := createOrOpenNamespace(ctx, func() (uintptr, error) {
		h, _, err := kernel.NewProc("CreatePrivateNamespaceW").Call(uintptr(unsafe.Pointer(sa)), boundary, uintptr(unsafe.Pointer(name)))
		return h, err
	}, func() (uintptr, error) {
		h, _, err := kernel.NewProc("OpenPrivateNamespaceW").Call(boundary, uintptr(unsafe.Pointer(name)))
		return h, err
	})
	if err != nil {
		return winhandle.Owner{}, err
	}
	return winhandle.Open(windows.Handle(h), "ownership namespace open"), nil
}

// namespaceAttempts bounds createOrOpenNamespace's rounds.
const namespaceAttempts = 5

// createOrOpenNamespace creates the private namespace, or opens it when it
// already exists. Between the create's ERROR_ALREADY_EXISTS and the open,
// the last other process holding the namespace can close it, and the open
// then fails because the namespace is gone; creating again succeeds. So a
// failed open starts another round, up to namespaceAttempts within ctx,
// rather than failing startup. Windows does not document which error that
// open returns, so every open failure but ERROR_ACCESS_DENIED (a caller
// outside the boundary, which no retry changes) gets another round. Any
// create error but ERROR_ALREADY_EXISTS is returned at once.
func createOrOpenNamespace(ctx context.Context, create, open func() (uintptr, error)) (uintptr, error) {
	var lastOpen error
	for range namespaceAttempts {
		if err := ctx.Err(); err != nil {
			return 0, errors.Join(err, lastOpen)
		}
		h, err := create()
		if h != 0 {
			return h, nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return 0, err
		}
		if h, err = open(); h != 0 {
			return h, nil
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, err
		}
		lastOpen = err
	}
	return 0, fmt.Errorf("private namespace existed at each create and was gone at each open, %d times: %w", namespaceAttempts, lastOpen)
}

func waitOwnershipPreparation(ctx context.Context, wait func() (uint32, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := wait()
		if err != nil {
			return err
		}
		switch result {
		case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
			// An interrupted initializer is safe to resume: the existing
			// preparation helper authenticates and recovers its durable stage.
			return nil
		case uint32(windows.WAIT_TIMEOUT):
		default:
			return fmt.Errorf("unexpected ownership preparation wait result %#x", result)
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
