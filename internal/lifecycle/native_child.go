package lifecycle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
	"github.com/AyoubAchour/net-switch/internal/service"
	gvlog "gvisor.dev/gvisor/pkg/log"
)

type nativeResult struct {
	Code   uint32
	Forced bool
	Err    error
}

func nativeChildEnvironment() []string {
	var result []string
	for _, entry := range service.ChildEnvironment() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOMEMLIMIT" && key != "GOGC" {
			result = append(result, entry)
		}
	}
	return append(result, "GOMEMLIMIT=512MiB")
}

func closeNativePipe(c io.Closer) error {
	err := c.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

type nativeProcess struct {
	alive          func() (bool, error)
	pid            uint32
	input          io.WriteCloser
	output, stderr io.ReadCloser
	resume         func() error
	wait           func(context.Context) (nativeResult, error)
	kill, close    func() error
	registrar      func(supervisor.Message) error
}

// NativeChildCommand is only a private bootstrap of the native service build.
// It never accepts policy or a target executable through command-line options.
func NativeChildCommand(args []string) error {
	if !nativeEngineBuild || len(args) != 3 {
		return errors.New("invalid native child bootstrap")
	}
	pid, err := strconv.ParseUint(args[2], 10, 32)
	if err != nil || pid == 0 {
		return errors.New("invalid supervisor identity")
	}
	if b, err := hex.DecodeString(args[1]); err != nil || len(b) != 16 {
		return errors.New("invalid private endpoint")
	}
	if err := verifyNativeParent(uint32(pid)); err != nil {
		return err
	}
	c, err := LoadConfig(args[0])
	if err != nil {
		return err
	}
	childLogs := supervisor.NewLog(os.Stderr)
	log.SetOutput(childLogs)
	gvlog.SetTarget(&gvlog.Writer{Next: childLogs})
	channel := supervisor.NewChannel(os.Stdin, os.Stdout)
	defer channel.Close()
	start, cancelStart := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStart()
	var key []byte
	select {
	case msg := <-channel.Messages():
		key, err = hex.DecodeString(msg.Key)
		if msg.Kind != "bootstrap" || err != nil || len(key) != 32 {
			return errors.New("invalid supervisor bootstrap")
		}
	case <-channel.Done():
		return io.ErrUnexpectedEOF
	case <-start.Done():
		return start.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := nativeProofBeforeReady(c.Data); err != nil {
		failure, finish := context.WithTimeout(context.Background(), time.Second)
		defer finish()
		_ = channel.Flush(failure, supervisor.Message{Kind: "complete", PID: uint32(os.Getpid()), Code: 1, Error: err.Error()})
		return err
	}
	var server atomic.Pointer[protocol.Server]
	var requested, disconnected atomic.Bool
	registrarAck := make(chan uint32, 1)
	if err := configureChildRegistrar(func(wait context.Context, msg supervisor.Message) error {
		started := nativeAwake()
		if err := channel.Send(wait, msg); err != nil {
			return fmt.Errorf("registrar PID %d capability send: %w", msg.PID, err)
		}
		select {
		case pid := <-registrarAck:
			if pid != msg.PID {
				return errors.New("registrar ACK identity mismatch")
			}
			return nil
		case <-channel.Done():
			return io.ErrClosedPipe
		case <-wait.Done():
			return fmt.Errorf("registrar PID %d capability sent; ACK not consumed after %s: %w", msg.PID, nativeAwake().Sub(started), wait.Err())
		}
	}); err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-channel.Done():
				disconnected.Store(true)
				cancel()
				return
			case msg := <-channel.Messages():
				s := server.Load()
				switch msg.Kind {
				case "resume":
					if s != nil {
						s.Resume()
					}
				case "stop":
					requested.Store(true)
					cancel()
				case "registrarAck":
					select {
					case registrarAck <- msg.PID:
					default:
						channel.Close()
					}
				case "state":
					if s == nil {
						channel.Close()
						continue
					}
					state, index, port, started, epoch := s.Supervision()
					if err := channel.Send(context.Background(), supervisor.Message{Kind: "state", Seq: msg.Seq, State: state, Index: index, Port: port, Instance: s.Instance, Started: started, Epoch: epoch}); err != nil {
						channel.Close()
					}
				default:
					channel.Close()
				}
			}
		}
	}()
	configure := func(options *host.Options) {
		options.HealthKey = key
		options.Listen = func() (host.Listener, error) { return listenNativeChild(args[1], uint32(pid)) }
		previous := options.Ready
		options.Ready = func(s *protocol.Server) {
			if previous != nil {
				previous(s)
			}
			server.Store(s)
			if err := channel.Send(ctx, supervisor.Message{Kind: "ready", PID: uint32(os.Getpid()), Instance: s.Instance}); err != nil {
				cancel()
			}
		}
	}
	err = runNativeChild(ctx, func() {}, c, func(s string) { log.Print(s) }, configure)
	if disconnected.Load() && !requested.Load() {
		err = errors.Join(err, errors.New("supervisor channel lost"))
	}
	end, cancelEnd := context.WithTimeout(context.Background(), time.Second)
	defer cancelEnd()
	message := supervisor.Message{Kind: "complete", Code: service.ExitCode(err), PID: uint32(os.Getpid())}
	if s := server.Load(); s != nil {
		message.Instance = s.Instance
	}
	if err != nil {
		message.Error = fmt.Sprint(err)
		if len(message.Error) > 1024 {
			message.Error = message.Error[:1024]
		}
	}
	if send := channel.Flush(end, message); send != nil {
		return errors.Join(err, send)
	}
	return err
}
