//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	index            int
	writeBuffer      [9010]byte
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
	// EXCL makes creation atomic: never attach to another process's adapter
	// if a name collision occurs between the journal intent and this ioctl.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_TUN_EXCL)
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
	// This is the kernel-to-engine ingress ring, distinct from the engine's
	// 1,024-packet output queue. Hold a full admission burst in wire order.
	if err := netlink.LinkSetTxQLen(l, v.IngressQueue); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, err
	}
	t := &Tun{device: device, index: v.Index, mtu: v.MTU, sizes: make([]int, device.BatchSize()), bufs: make([][]byte, device.BatchSize())}
	for i := range t.bufs {
		t.bufs[i] = make([]byte, 65535)
	}
	ok = true
	return t, nil
}
func (t *Tun) MTU() int { return t.mtu }
func (t *Tun) Stats() any {
	l, err := netlink.LinkByIndex(t.index)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	s := l.Attrs().Statistics
	if s == nil {
		return nil
	}
	return map[string]uint64{"ingressPackets": s.TxPackets, "ingressDropped": s.TxDropped, "egressPackets": s.RxPackets, "egressDropped": s.RxDropped}
}
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
	if len(packet) > 9000 {
		return io.ErrShortBuffer
	}
	b := t.writeBuffer[:10+len(packet)]
	clear(b[:10])
	copy(b[10:], packet)
	stop := context.AfterFunc(ctx, func() { t.device.Close() })
	defer stop()
	n, err := t.device.Write([][]byte{b}, 10)
	// The pinned Linux implementation returns bytes (including virtio's
	// header), despite Device.Write's comment saying packets. Treat a real
	// short write as failure, not every successful packet as failure.
	if err == nil && n != len(b) {
		return fmt.Errorf("TUN wrote %d of %d bytes: %w", n, len(b), io.ErrShortWrite)
	}
	return err
}
