//go:build linux

package linux

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// Tun adapts wireguard-go's ordered GSO splitting to our single-packet seam.
// The dependency is used unmodified, under its MIT license, as the design
// specifies. We create the descriptor ourselves to reserve its exact index
// in the ownership journal before TUNSETIFF.
type Tun struct {
	device           tun.Device
	readMu, writeMu  sync.Mutex
	bufs             [][]byte
	sizes            []int
	next, count, mtu int
}

func openTun(v tunObject) (*Tun, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			unix.Close(fd)
		}
	}()
	if err := unix.IoctlSetPointerInt(fd, unix.TUNSETIFINDEX, v.Index); err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(v.Name)
	if err != nil {
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}
	device, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	owned = false // the library now owns fd, including its error paths
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			device.Close()
		}
	}()
	if name != v.Name {
		return nil, errors.New("TUN name changed")
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if l.Attrs().Index != v.Index {
		return nil, errors.New("TUN index changed")
	}
	if err := netlink.LinkSetAlias(l, v.Alias); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetMTU(l, v.MTU); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, err
	}
	t := &Tun{device: device, mtu: v.MTU, sizes: make([]int, device.BatchSize()), bufs: make([][]byte, device.BatchSize())}
	for i := range t.bufs {
		t.bufs[i] = make([]byte, 65535)
	}
	ok = true
	return t, nil
}
func (t *Tun) MTU() int     { return t.mtu }
func (t *Tun) Close() error { return t.device.Close() }
func (t *Tun) ReadPacket(ctx context.Context, out []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if t.next == t.count {
		stop := context.AfterFunc(ctx, func() { t.device.Close() })
		defer stop()
		n, err := t.device.Read(t.bufs, t.sizes, 0)
		if err != nil {
			return 0, err
		}
		t.next, t.count = 0, n
	}
	if t.count == 0 {
		return 0, nil
	}
	n := t.sizes[t.next]
	if n > len(out) {
		return 0, io.ErrShortBuffer
	}
	copy(out, t.bufs[t.next][:n])
	t.next++
	return n, nil
}
func (t *Tun) WritePacket(ctx context.Context, packet []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// wireguard-go needs ten bytes before the IP header for virtio metadata.
	b := make([]byte, 10+len(packet))
	copy(b[10:], packet)
	stop := context.AfterFunc(ctx, func() { t.device.Close() })
	defer stop()
	n, err := t.device.Write([][]byte{b}, 10)
	if err == nil && n != 1 {
		return os.ErrInvalid
	}
	return err
}
