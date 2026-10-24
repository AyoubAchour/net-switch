package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
	"github.com/AyoubAchour/net-switch/internal/service"
)

type nativeHostChannel struct {
	*supervisor.Channel
	ready     chan supervisor.Message
	state     chan supervisor.Message
	failure   chan error
	complete  atomic.Pointer[supervisor.Message]
	seq       atomic.Uint64
	processed chan struct{}
}

func nativeHostMessages(p *nativeProcess) *nativeHostChannel {
	h := &nativeHostChannel{Channel: supervisor.NewChannel(p.output, p.input), ready: make(chan supervisor.Message, 1), state: make(chan supervisor.Message, 1), failure: make(chan error, 1), processed: make(chan struct{})}
	go func() {
		defer close(h.processed)
		instance := ""
		fail := func(err error) {
			select {
			case h.failure <- err:
			default:
			}
			h.Close()
		}
		for m := range h.Messages() {
			switch m.Kind {
			case "ready":
				if b, err := hex.DecodeString(m.Instance); err != nil || len(b) != 16 || m.PID != p.pid || instance != "" {
					fail(errors.New("native child readiness identity mismatch"))
					return
				}
				instance = m.Instance
				h.ready <- m
			case "registrar":
				if instance == "" {
					fail(errors.New("registrar before child readiness"))
					return
				}
				if err := p.registrar(m); err != nil {
					fail(err)
					return
				}
				if err := h.Send(context.Background(), supervisor.Message{Kind: "registrarAck", PID: m.PID}); err != nil {
					fail(err)
					return
				}
			case "state":
				if m.Instance != instance {
					fail(errors.New("private state instance mismatch"))
					return
				}
				if m.Seq != h.seq.Load() {
					continue
				}
				select {
				case h.state <- m:
				default:
					// A timed-out poll may have left one older reply buffered.
					// It cannot consume the next poll's reserved response slot.
					select {
					case old := <-h.state:
						if old.Seq >= m.Seq {
							fail(errors.New("unsolicited private state"))
							return
						}
					default:
					}
					select {
					case h.state <- m:
					default:
						fail(errors.New("private state queue exhausted"))
						return
					}
				}
			case "complete":
				if instance == "" && m.PID == p.pid {
					fail(fmt.Errorf("native child startup failed: code=%d error=%s", m.Code, m.Error))
					return
				}
				if m.Instance != instance || instance == "" || m.PID != p.pid || h.complete.Load() != nil {
					fail(errors.New("native completion identity mismatch"))
					return
				}
				h.complete.Store(&m)
			default:
				fail(errors.New("unknown private child message"))
				return
			}
		}
	}()
	return h
}
func (h *nativeHostChannel) status(ctx context.Context) (supervisor.Message, error) {
	seq := h.seq.Add(1)
	if err := h.Send(ctx, supervisor.Message{Kind: "state", Seq: seq}); err != nil {
		return supervisor.Message{}, err
	}
	for {
		select {
		case m := <-h.state:
			if m.Seq == seq {
				return m, nil
			}
		case <-h.Done():
			return supervisor.Message{}, io.ErrUnexpectedEOF
		case <-ctx.Done():
			return supervisor.Message{}, ctx.Err()
		}
	}
}

type nativeLog func(string)

func (l nativeLog) Write(b []byte) (int, error) { l(string(b)); return len(b), nil }

func nativeEngineService(ctx context.Context, ready func(), c Config, report func(string)) (result error) {
	logs := supervisor.NewLog(nativeLog(nativeProofLogSink(ctx, c.Data, report)))
	log := func(s string) { logs.Write([]byte(s)) }
	var token [16]byte
	var key [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(token[:])
	if err := refuseStandInStore(c.Data); err != nil {
		return err
	}
	listener, err := listenNativePublic()
	if err != nil {
		return err
	}
	defer listener.Close()
	// Reserve before capture or application admission, then retain this one
	// socket. Full application port pools must not starve watchdog health.
	healthSocket, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("reserve supervisor probe socket: %w", err)
	}
	defer healthSocket.Close()
	if err := healthSocket.SetReadBuffer(4096); err != nil {
		return err
	}
	if err := healthSocket.SetWriteBuffer(4096); err != nil {
		return err
	}
	p, err := startNativeChild(c.Data, nonce)
	if err != nil {
		return err
	}
	defer func() {
		if err := p.close(); err != nil {
			result = errors.Join(result, err)
		}
	}()
	h := nativeHostMessages(p)
	defer h.Close()
	go io.CopyBuffer(logs, struct{ io.Reader }{p.stderr}, make([]byte, 4096))
	exited := make(chan nativeResult, 1)
	go func() { r, err := p.wait(context.Background()); r.Err = errors.Join(r.Err, err); exited <- r }()
	if err := h.Send(ctx, supervisor.Message{Kind: "bootstrap", Key: hex.EncodeToString(key[:])}); err != nil {
		return err
	}
	if err := p.resume(); err != nil {
		return err
	}
	instance := ""
	var raw nativeResult
	gotExit := false
	startup := time.NewTimer(15 * time.Second) // bootstrap precedes routing/registrar startup
	select {
	case m := <-h.ready:
		instance = m.Instance
	case raw = <-exited:
		gotExit = true
		result = errors.New("native child died before readiness")
	case err := <-h.failure:
		result = err
	case <-h.Done():
		result = errors.New("native child transport lost before readiness")
	case <-startup.C:
		result = errors.New("native child readiness timed out")
	case <-ctx.Done():
		result = ctx.Err()
	}
	startup.Stop()
	run, cancel := context.WithCancel(context.Background())
	defer cancel()
	var clients sync.WaitGroup
	probe := &nativeForwardingHealth{channel: h, key: key, socket: healthSocket}
	acceptErr := make(chan error, 1)
	if result == nil {
		alive, err := p.alive()
		if err != nil || !alive || ctx.Err() != nil {
			result = errors.Join(errors.New("child unavailable before service readiness"), err, ctx.Err())
		}
	}
	if result == nil {
		out, err := host.ReadOutcome(c.Data, instance)
		if err == nil {
			out.Child = &host.ChildOutcome{PID: p.pid}
			err = writeOutcome(c.Data, out)
		}
		if err != nil {
			result = err
		} else {
			log(fmt.Sprintf("native supervisor ready child_pid=%d instance=%s", p.pid, instance))
			clients.Go(func() {
				slots := make(chan struct{}, supervisor.Connections)
				for {
					public, err := listener.Accept(run)
					if err != nil {
						if nativeRefused(err) {
							continue
						}
						select {
						case acceptErr <- err:
						default:
						}
						return
					}
					select {
					case slots <- struct{}{}:
					default:
						public.Close()
						continue
					}
					clients.Go(func() {
						defer func() { <-slots }()
						defer public.Close()
						dial, cancelDial := context.WithTimeout(run, 3*time.Second)
						private, err := dialNativeChild(dial, nonce, p.pid)
						cancelDial()
						if err != nil {
							return
						}
						supervisor.Relay(run, public, private)
					})
				}
			})
		}
	}
	if result == nil {
		watch := time.NewTimer(0) // first check at readiness, not one tick later
		defer watch.Stop()
		health := healthWatch{limit: 18 * time.Second}
		var pause powerPause
		events := service.Events(ctx)
		service.SupervisionProgress()
		ready() // child identity, private transport and supervision are armed
	watching:
		for {
			for _, event := range events.Take() {
				if event.Suspend || event.Resume {
					health = healthWatch{limit: 18 * time.Second}
					probe.state = "" // restart lifecycle's awake-time window on resume
					pause.set(event.Suspend, nativeAwake())
				}
				if event.Resume {
					if err := h.Send(run, supervisor.Message{Kind: "resume"}); err != nil {
						result = err
						break watching
					}
				}
			}
			select {
			case raw = <-exited:
				gotExit = true
				break watching
			case result = <-h.failure:
				break watching
			case result = <-acceptErr:
				break watching
			case <-ctx.Done():
				break watching
			case <-events.Ready():
				continue
			case <-watch.C:
				checkStarted := time.Now()
				if pause.expired(nativeAwake()) {
					health = healthWatch{limit: 18 * time.Second}
				}
				if !pause.on {
					before := probe.success
					result = health.check(ctx, probe, nativeAwake)
					if probe.success != before && (before == 0 || probe.success%10 == 0) {
						log(fmt.Sprintf("NATIVE_HEALTH instance=%s child_pid=%d passes=%d failures=%d at=%s", instance, p.pid, probe.success, probe.failures, time.Now().UTC().Format(time.RFC3339Nano)))
					}
				}
				// Timed-out probes have already consumed the tick interval.
				watch.Reset(max(0, time.Second-time.Since(checkStarted)))
				if ctx.Err() != nil {
					result = nil
					break watching
				}
				service.SupervisionProgress() // completed probe, including timeouts
				if result != nil {
					log(result.Error())
					break watching
				}
			}
		}
	}
	if !gotExit && result == nil {
		stop, cancelStop := context.WithTimeout(context.Background(), 20*time.Second)
		if err := h.Send(stop, supervisor.Message{Kind: "stop"}); err != nil {
			result = err
		} else {
			select {
			case raw = <-exited:
				gotExit = true
			case <-stop.Done():
				result = errors.New("native child graceful stop timed out")
			}
		}
		cancelStop()
	}
	finishBy := time.Now().Add(6 * time.Second)
	listener.Close()
	if !gotExit {
		cancel()
		log(fmt.Sprintf("NATIVE_TERMINATE instance=%s child_pid=%d at=%s", instance, p.pid, time.Now().UTC().Format(time.RFC3339Nano)))
		result = errors.Join(result, p.kill())
		join, cancelJoin := context.WithTimeout(context.Background(), 2*time.Second)
		select {
		case raw = <-exited:
			gotExit = true
		case <-join.Done():
			result = errors.Join(result, errors.New("native child did not exit within termination bound"))
		}
		cancelJoin()
	}
	if !gotExit {
		return result
	} // never clean ownership while child is alive
	log(fmt.Sprintf("NATIVE_TERMINATED instance=%s child_pid=%d at=%s forced=%t", instance, p.pid, time.Now().UTC().Format(time.RFC3339Nano), raw.Forced))
	// A completed failed Stop also carries a final error reply. Preserve the
	// same bounded public-relay drain before cancellation on failure exits.
	if !raw.Forced {
		drained := make(chan struct{})
		go func() { clients.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(500 * time.Millisecond):
		}
	}
	cancel()
	// Drain the completion frame already in the pipe even if process wait won
	// the scheduling race. Bounded independently of a public reader or logs.
	select {
	case <-h.processed:
	case <-time.After(time.Second):
		result = errors.Join(result, errors.New("private child EOF was not drained"))
	}
	h.Close()
	clients.Wait()
	result = errors.Join(result, raw.Err)
	complete := h.complete.Load()
	valid := complete != nil && complete.Code == int(raw.Code) && !raw.Forced
	if !valid {
		result = errors.Join(result, fmt.Errorf("native child incomplete/forced exit code=%d forced=%t", raw.Code, raw.Forced))
	}
	if raw.Code != 0 && raw.Code != 3 {
		detail := ""
		if complete != nil {
			detail = complete.Error
		}
		result = errors.Join(result, fmt.Errorf("native child failed code=%d: %s", raw.Code, detail))
	}
	if instance != "" {
		out, err := host.ReadOutcome(c.Data, instance)
		if err == nil {
			out.Child = &host.ChildOutcome{PID: p.pid, Code: raw.Code, Forced: raw.Forced, Completed: valid, HostLogsDropped: logs.Dropped.Load(), HostHealthPasses: probe.success, HostHealthFailures: probe.failures}
			if result != nil {
				out.Child.Error = result.Error()
				out.Reason = "failure"
			}
			err = writeOutcome(c.Data, out)
		}
		result = errors.Join(result, err)
	}
	// The child and every registrar have exited; only now acquire its released
	// native lifetime lock to reconcile journaled OS objects.
	cleanupDeadline := time.Now().Add(4 * time.Second)
	if finishBy.Before(cleanupDeadline) {
		cleanupDeadline = finishBy
	}
	cleanup, cancelCleanup := context.WithDeadline(context.Background(), cleanupDeadline)
	cleanupErr := cleanupNative(cleanup, c.Data)
	cancelCleanup()
	cleanupErr = errors.Join(cleanupErr, p.close())
	log(fmt.Sprintf("NATIVE_CLEANED instance=%s child_pid=%d at=%s error=%v", instance, p.pid, time.Now().UTC().Format(time.RFC3339Nano), cleanupErr))
	result = errors.Join(result, cleanupErr)
	if instance != "" {
		out, err := host.ReadOutcome(c.Data, instance)
		if err == nil && out.Child != nil {
			if result != nil {
				out.Child.Error = result.Error()
			}
			if cleanupErr != nil {
				out.State = "failed"
				out.Error = cleanupErr.Error()
			}
			err = writeOutcome(c.Data, out)
		}
		result = errors.Join(result, err)
	}
	log(fmt.Sprintf("native supervisor outcome child_pid=%d raw=%d forced=%t completed=%t error=%v", p.pid, raw.Code, raw.Forced, valid, result))
	if result == nil && raw.Code == 3 {
		return nativeChildExit(3)
	}
	return result
}

type nativeChildExit int

func (e nativeChildExit) Error() string       { return fmt.Sprintf("native child completed with exit %d", e) }
func (e nativeChildExit) EngineExitCode() int { return int(e) }
