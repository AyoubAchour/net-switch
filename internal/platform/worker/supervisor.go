// Package worker owns the narrow subprocess seam for blocking OS reads.
package worker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Process interface {
	Output() io.ReadCloser
	Wait() error
	Kill() error
	Close() error
}
type Launch func(string, []string) (Process, error)
type Supervisor struct {
	Executable string
	Launch     Launch
	Silent     time.Duration
}

func (s Supervisor) launch(args []string) (Process, error) {
	if s.Launch != nil {
		return s.Launch(s.Executable, args)
	}
	return Start(s.Executable, args)
}
func (s Supervisor) Once(ctx context.Context, operation string, args map[string]any) (any, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, err := s.launch([]string{"worker", "query", operation, base64.RawURLEncoding.EncodeToString(b)})
	if err != nil {
		return nil, err
	}
	defer p.Close()
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, e := io.ReadAll(io.LimitReader(p.Output(), 4*1024*1024+1))
		if len(b) > 4*1024*1024 {
			_ = p.Kill()
			e = fmt.Errorf("worker result exceeds 4 MiB")
		}
		wait := p.Wait()
		if e == nil {
			e = wait
		}
		done <- result{b, e}
	}()
	select {
	case <-ctx.Done():
		_ = p.Kill()
		<-done
		return nil, fmt.Errorf("%s worker did not finish: %w", operation, ctx.Err())
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("%s worker: %w (%s)", operation, r.err, r.b)
		}
		var envelope struct {
			Value any    `json:"value"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(r.b, &envelope); err != nil {
			return nil, fmt.Errorf("%s worker returned invalid JSON: %w", operation, err)
		}
		if envelope.Error != "" {
			return nil, fmt.Errorf("%s: %s", operation, envelope.Error)
		}
		return envelope.Value, nil
	}
}
func (s Supervisor) Stream(ctx context.Context, mode string, args []string, emit func([]byte), report func(error)) {
	backoff := time.Second
	silent := s.Silent
	if silent == 0 {
		silent = 10 * time.Second
		if mode == "network" {
			silent = 30 * time.Second
		}
	}
	for ctx.Err() == nil {
		p, err := s.launch(append([]string{"worker", mode}, args...))
		if err == nil {
			runCtx, stopReader := context.WithCancel(ctx)
			lines := make(chan []byte, 1)
			done := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(p.Output())
				scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
				for scanner.Scan() {
					b := append([]byte{}, scanner.Bytes()...)
					select {
					case lines <- b:
					case <-runCtx.Done():
						return
					}
				}
				done <- scanner.Err()
			}()
			timer := time.NewTimer(silent)
			running := true
			for running {
				select {
				case <-ctx.Done():
					running = false
				case b := <-lines:
					if !json.Valid(b) {
						report(fmt.Errorf("%s worker returned invalid JSON", mode))
						continue
					}
					emit(b)
					backoff = time.Second
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(silent)
				case e := <-done:
					err = e
					if err == nil {
						err = fmt.Errorf("%s worker stopped", mode)
					}
					running = false
				case <-timer.C:
					err = fmt.Errorf("%s worker stopped reporting for %s; killing and restarting it", mode, silent)
					running = false
				}
			}
			timer.Stop()
			stopReader()
			_ = p.Kill()
			_ = p.Wait()
			_ = p.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(30*time.Second, backoff*2)
	}
}
