package worker

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProcess struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	killed chan struct{}
	once   sync.Once
}

func (p *fakeProcess) Output() io.ReadCloser { return p.reader }
func (p *fakeProcess) Wait() error           { <-p.killed; return nil }
func (p *fakeProcess) Kill() error {
	p.once.Do(func() {
		if p.writer != nil {
			p.writer.Close()
		}
		close(p.killed)
	})
	return nil
}
func (p *fakeProcess) Close() error { _ = p.Kill(); return p.reader.Close() }
func TestHungWorkerIsKilledBeforeReturningTimeout(t *testing.T) {
	r, w := io.Pipe()
	p := &fakeProcess{reader: r, writer: w, killed: make(chan struct{})}
	supervisor := Supervisor{Executable: "fake", Launch: func(string, []string) (Process, error) { return p, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := supervisor.Once(ctx, "network", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	select {
	case <-p.killed:
	default:
		t.Fatal("returned before terminating worker")
	}
}
func TestMalformedWorkerReplyIsNotAnEmptySnapshot(t *testing.T) {
	p := &fakeProcess{reader: io.NopCloser(strings.NewReader("{invalid")), killed: make(chan struct{})}
	close(p.killed)
	p.once.Do(func() {})
	s := Supervisor{Launch: func(string, []string) (Process, error) { return p, nil }}
	if _, err := s.Once(context.Background(), "network", nil); err == nil {
		t.Fatal("invalid snapshot was accepted")
	}
}
