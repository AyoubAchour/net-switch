//go:build windows

package main

import (
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// Use the documented session API directly: wireguard/tun.Write hides
// ERROR_BUFFER_OVERFLOW as success, making lost replies impossible to count.
// Keep the same 8 MiB rings. One reader and one writer own the packet buffers.
type observedDevice struct {
	mu sync.RWMutex
	adapter *wintun.Adapter
	session wintun.Session
	closed bool
	ringFull atomic.Uint64
	readErrors atomic.Uint64
	writeErrors atomic.Uint64
}

func openDevice() (*observedDevice, error) {
	a, err := wintun.CreateAdapter("TestISP", "TestISP", nil)
	if err != nil { return nil, err }
	s, err := a.StartSession(0x800000)
	if err != nil { a.Close(); return nil, err }
	return &observedDevice{adapter: a, session: s}, nil
}

func (d *observedDevice) Read(buf []byte) (int, error) {
	for {
		d.mu.RLock()
		if d.closed { d.mu.RUnlock(); return 0, os.ErrClosed }
		packet, err := d.session.ReceivePacket()
		if err == nil {
			n := copy(buf, packet)
			d.session.ReleaseReceivePacket(packet)
			d.mu.RUnlock()
			return n, nil
		}
		if err == windows.ERROR_NO_MORE_ITEMS {
			// Bound the wait while holding the session alive. Close takes the
			// write lock before ending it, so no syscall uses a freed handle.
			_, err = windows.WaitForSingleObject(d.session.ReadWaitEvent(), 10)
			d.mu.RUnlock()
			if err == nil { continue }
		} else { d.mu.RUnlock() }
		d.readErrors.Add(1)
		return 0, err
	}
}

func (d *observedDevice) Write(data []byte) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed { return os.ErrClosed }
	packet, err := d.session.AllocateSendPacket(len(data))
	if err != nil {
		if err == windows.ERROR_BUFFER_OVERFLOW { d.ringFull.Add(1) } else { d.writeErrors.Add(1) }
		return err
	}
	copy(packet, data)
	d.session.SendPacket(packet)
	return nil
}

func (d *observedDevice) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed { return }
	d.closed = true
	d.session.End()
	d.adapter.Close()
}
