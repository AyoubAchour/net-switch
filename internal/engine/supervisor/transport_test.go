package supervisor

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRelayPreservesFinalFrameBeforeEOF(t *testing.T) {
	for _, want := range []string{"{\"id\":\"stop\",\"result\":true}\n", "{\"id\":\"stop\",\"error\":\"cleanup failed\"}\n"} {
		t.Run(want, func(t *testing.T) { testFinalFrame(t, want) })
	}
}

func testFinalFrame(t *testing.T, want string) {
	t.Helper()
	client, public := net.Pipe()
	private, engine := net.Pipe()
	defer client.Close()
	defer engine.Close()
	done := make(chan struct{})
	go func() { Relay(context.Background(), public, private); close(done) }()
	go func() { Write(engine, []byte(want)); engine.Close() }()
	client.SetReadDeadline(time.Now().Add(time.Second))
	got, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not join")
	}
}
func TestSlowRelayAndLogReaderCannotHoldPrivateCompletion(t *testing.T) {
	client, public := net.Pipe()
	private, engine := net.Pipe()
	defer client.Close()
	defer engine.Close()
	done := make(chan struct{})
	go func() { Relay(context.Background(), public, private); close(done) }()
	go func() {
		for range 10 {
			if Write(engine, []byte("{\"id\":\"bulk\"}\n")) != nil {
				return
			}
		}
	}()
	a, b := net.Pipe()
	c := NewChannel(a, a)
	defer c.Close()
	defer b.Close()
	go func() { Write(b, []byte("{\"kind\":\"complete\",\"code\":3}\n")); b.Close() }()
	select {
	case m := <-c.Messages():
		if m.Kind != "complete" || m.Code != 3 {
			t.Fatal(m)
		}
	case <-time.After(time.Second):
		t.Fatal("bulk relay blocked private completion")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow reader retained relay")
	}
	r, w := io.Pipe()
	logs := NewLog(w)
	defer r.Close()
	defer w.Close()
	for range 256 {
		logs.Write(make([]byte, 8192))
	}
	if logs.Dropped.Load() == 0 {
		t.Fatal("blocked sink did not exercise log bound")
	}
}
func TestPrivateCompletionIsDrainedAfterEOF(t *testing.T) {
	a, b := net.Pipe()
	c := NewChannel(a, a)
	defer c.Close()
	go func() { Write(b, []byte("{\"kind\":\"ready\"}\n{\"kind\":\"complete\",\"code\":3}\n")); b.Close() }()
	<-c.Done()
	var got []string
	for m := range c.Messages() {
		got = append(got, m.Kind)
	}
	if strings.Join(got, ",") != "ready,complete" {
		t.Fatal(got)
	}
}
func TestFrameLimitAndPartialFrame(t *testing.T) {
	for _, input := range []string{strings.Repeat("a", 4097) + "\n", "partial"} {
		if _, err := Line(bufio.NewReader(strings.NewReader(input)), 4096); err == nil {
			t.Fatal("accepted bad frame")
		}
	}
}
