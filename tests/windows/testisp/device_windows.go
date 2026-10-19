//go:build windows

package main

import (
	"context"
	"io"
	"log"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/wintun"
)

// This identity belongs only to the hosted TestISP fixture, never NetSwitch.
var deviceConfig = wintun.Config{
	Name: "TestISP", GUID: "{E66D91A5-76B7-4A95-95CB-E2D87706E994}",
	TunnelType: "TestISP", MTU: 1500, Capacity: 0x800000,
}

// Keep the gateway's single-packet boundary and 8 MiB rings. The shared session
// owns cancellation, recovery and wake-ups; the DLL only manages the adapter.
type observedDevice struct {
	adapter     *wintun.Adapter
	session     *wintun.Session
	writeDrops  atomic.Uint64
	readErrors  atomic.Uint64
	writeErrors atomic.Uint64
}

func recoverDevice() error {
	err := wintun.RecoverAfterCrash(deviceConfig)
	if err == nil {
		log.Print("TestISP recovery check complete")
	}
	return err
}

func openDevice() (*observedDevice, error) {
	if err := recoverDevice(); err != nil {
		return nil, err
	}
	a, err := wintun.Create(deviceConfig)
	if err != nil {
		return nil, err
	}
	s, err := a.StartSession()
	if err != nil {
		a.Close()
		return nil, err
	}
	return &observedDevice{adapter: a, session: s}, nil
}

func (d *observedDevice) Read(buf []byte) (int, error) {
	n, err := d.session.ReadPacket(context.Background(), buf)
	if err != nil {
		d.readErrors.Add(1)
	}
	return n, err
}

func (d *observedDevice) Write(data []byte) error {
	n, err := d.session.WriteBatch([][]byte{data})
	if err != nil {
		d.writeErrors.Add(1)
	} else if n != 1 {
		d.writeDrops.Add(1)
		return io.ErrShortWrite
	}
	return err
}

func (d *observedDevice) Close() {
	if err := d.adapter.Close(); err != nil {
		log.Printf("TestISP session close: %v", err)
	}
}
