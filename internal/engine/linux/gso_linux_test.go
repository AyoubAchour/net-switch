//go:build linux

package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func requireKernelNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("NETSWITCH_ISOLATED_NETNS") != "1" {
		t.Skip("requires CI isolated network namespace")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || self == "" || self == init {
		t.Fatal("refusing kernel mutation outside isolated root test")
	}
}

func TestKernelTCPMaxseg88KeepsTunAlive(t *testing.T) {
	requireKernelNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	p, err := New(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	device, err := p.OpenTun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	p.objects.tun.BindIOContext(ctx)
	link := ns.NewLink()
	stack, err := ns.New(link, ns.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Wait()
	defer stack.Close()
	var pumps sync.WaitGroup
	failures := make(chan error, 4)
	result := make(chan []byte, 2)
	forwarder := gtcp.NewForwarder(stack, 1<<20, 4, func(request *gtcp.ForwarderRequest) {
		var q waiter.Queue
		ep, err := request.CreateEndpoint(&q)
		request.Complete(err != nil)
		if err != nil {
			failures <- fmt.Errorf("handshake: %s", err)
			return
		}
		c := gonet.NewTCPConn(&q, ep)
		defer c.Close()
		c.SetDeadline(time.Now().Add(35 * time.Second))
		hash := sha256.New()
		if _, err := io.Copy(hash, c); err != nil {
			failures <- err
			return
		}
		result <- hash.Sum(nil)
	})
	stack.SetTransportProtocolHandler(gtcp.ProtocolNumber, forwarder.HandlePacket)
	pumps.Go(func() {
		data := make([]byte, 65535)
		for ctx.Err() == nil {
			n, err := device.ReadPacket(ctx, data)
			if err != nil {
				if ctx.Err() == nil {
					failures <- err
				}
				return
			}
			if n == 0 {
				continue
			}
			protocol := header.IPv4ProtocolNumber
			if data[0]>>4 == 6 {
				protocol = header.IPv6ProtocolNumber
			}
			packet := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(data[:n]))})
			link.InjectInbound(protocol, packet)
			packet.DecRef()
		}
	})
	pumps.Go(func() {
		for {
			packet := link.Read(ctx)
			if packet == nil {
				return
			}
			if err := device.WritePacket(ctx, packet); err != nil {
				if ctx.Err() == nil {
					failures <- err
				}
				return
			}
		}
	})
	defer func() { cancel(); device.Close(); pumps.Wait() }()
	for _, mss := range []int{88, 1460} {
		dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
			var optionErr error
			err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss) })
			if err != nil {
				return err
			}
			return optionErr
		}}
		conn, err := dialer.DialContext(ctx, "tcp4", "198.18.0.2:23456")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		data := bytes.Repeat([]byte("bounded GSO segments\n"), 100000)
		want := sha256.Sum256(data)
		if _, err := conn.Write(data); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.(*net.TCPConn).CloseWrite()
		select {
		case got := <-result:
			if !bytes.Equal(got, want[:]) {
				t.Fatal("payload changed across GSO split")
			}
		case err := <-failures:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		conn.Close()
	}
	if drops := p.objects.tun.readErrors.Load(); drops == 0 {
		t.Fatal("TCP_MAXSEG=88 did not exercise the GSO overflow")
	} else {
		t.Logf("recovered from %d oversized GSO batches; subsequent normal TCP survived", drops)
	}
}
