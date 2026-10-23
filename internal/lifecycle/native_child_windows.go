package lifecycle

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	"github.com/AyoubAchour/net-switch/internal/platform/winchild"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func startNativeChild(data, nonce string) (*nativeProcess, error) {
	p, err := winchild.StartSelf(winchild.Options{Args: []string{"native-child", data, nonce, strconv.Itoa(os.Getpid())}, Env: nativeChildEnvironment(), RegistrarBreakaway: true})
	if err != nil {
		return nil, err
	}
	return &nativeProcess{pid: p.Identity.PID, input: p.Input, output: p.Output, stderr: p.Errors, resume: p.Resume, kill: p.Terminate, close: p.Close, alive: p.Alive,
		wait: func(ctx context.Context) (nativeResult, error) {
			r, err := p.Wait(ctx)
			return nativeResult{Code: r.Code, Forced: r.Forced}, err
		},
		registrar: func(m supervisor.Message) error {
			return p.TrackRegistrar(winchild.Registrar{PID: m.PID, Handle: m.Handle})
		}}, nil
}
func verifyNativeParent(uint32) error { return winchild.CheckRegistrarParent() }
func configureChildRegistrar(observe func(context.Context, supervisor.Message) error) error {
	return wintun.ConfigureSupervisorChild(func(ctx context.Context, r winchild.Registrar) error {
		return observe(ctx, supervisor.Message{Kind: "registrar", PID: r.PID, Handle: r.Handle})
	})
}
func listenNativePublic() (host.Listener, error) {
	return winengine.ListenPipe(winengine.EnginePipe, false)
}
func listenNativeChild(nonce string, pid uint32) (host.Listener, error) {
	return winengine.ListenChildPipe(nonce, pid)
}
func dialNativeChild(ctx context.Context, nonce string, pid uint32) (io.ReadWriteCloser, error) {
	return winengine.DialChildPipe(ctx, nonce, pid)
}
func nativeRefused(err error) bool { return winengine.PeerRefused(err) }
func nativeAwake() time.Time       { return protocol.AwakeNow() }
func bindHealthSocket(raw syscall.RawConn, index int) error {
	var inner error
	err := raw.Control(func(fd uintptr) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(index))
		inner = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31 /* IP_UNICAST_IF */, int(binary.LittleEndian.Uint32(b[:])))
	})
	if err != nil {
		return err
	}
	return inner
}

func connectHealthSocket(raw syscall.RawConn, port uint16) error {
	var inner error
	err := raw.Control(func(fd uintptr) {
		inner = windows.Connect(windows.Handle(fd), &windows.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: int(port)})
	})
	if err != nil {
		return err
	}
	return inner
}
