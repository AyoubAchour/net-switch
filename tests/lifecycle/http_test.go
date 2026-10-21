package lifecycle_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func httpFlood(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	dialed := time.Now()
	for range 64 {
		c, err := net.DialTimeout("tcp4", u.Host, 2*time.Second)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(c, "GET /api/state HTTP/1.1\r\nHost: ")
		held = append(held, c)
	}
	// Admission refuses a user's connections beyond its cap at once; the
	// old code would have kept all 64 until the header deadline.
	closedBy := func(conns []net.Conn, deadline time.Time) (open, closed []net.Conn) {
		for _, c := range conns {
			c.SetReadDeadline(deadline)
			if _, err := c.Read(make([]byte, 1)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				closed = append(closed, c)
			} else {
				open = append(open, c)
			}
		}
		return open, closed
	}
	open, refused := closedBy(held, time.Now().Add(1500*time.Millisecond))
	if time.Since(dialed) > 4*time.Second {
		return fmt.Errorf("classification took %s, too close to the header deadline", time.Since(dialed))
	}
	fmt.Printf("HTTP attack handles held=%d refused=%d\n", len(open), len(refused))
	// Read and header deadlines: the admitted partial headers must be closed
	// by the server about five seconds after they were accepted.
	stillOpen, timedOut := closedBy(open, dialed.Add(8*time.Second))
	fmt.Printf("HTTP header deadline closed=%d open=%d after=%s\n", len(timedOut), len(stillOpen), time.Since(dialed).Round(time.Millisecond))
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

// httpChurn opens and immediately closes HTTP connections from several
// workers, so every one of them goes through identity admission.
func httpChurn(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	var opened atomic.Uint64
	stop := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c, err := net.DialTimeout("tcp4", u.Host, time.Second); err == nil {
					c.Close()
					opened.Add(1)
				}
			}
		})
	}
	time.Sleep(time.Second)
	fmt.Printf("HTTP churn running: %d connections in the first second\n", opened.Load())
	_, _ = io.Copy(io.Discard, os.Stdin)
	close(stop)
	workers.Wait()
	fmt.Printf("HTTP churn total=%d\n", opened.Load())
	return nil
}

// httpLatency makes sequential owner requests on fresh connections, so each
// one waits for admission, and prints the slowest and the median.
func httpLatency(rawURL, token string) error {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	var samples []time.Duration
	for range 20 {
		req, err := http.NewRequest("GET", rawURL+"api/state", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Token", token)
		started := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("owner request returned %d", resp.StatusCode)
		}
		samples = append(samples, time.Since(started))
	}
	slices.Sort(samples)
	fmt.Printf("owner latency max=%dms median=%dms\n", samples[len(samples)-1].Milliseconds(), samples[len(samples)/2].Milliseconds())
	return nil
}

func ownerLatency(t *testing.T, owner actor, url, token string) (maxMS, medianMS int) {
	t.Helper()
	exe, _ := os.Executable()
	b, err := owner.command(exe, "client", "http-latency", url, token).CombinedOutput()
	if err != nil {
		t.Fatal("owner latency probe", err, string(b))
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "owner latency max=%dms median=%dms", &maxMS, &medianMS); err != nil {
		t.Fatal("owner latency output", string(b), err)
	}
	return maxMS, medianMS
}

// httpChurnLatency measures the owner's HTTP latency while another user
// churns connections through admission, which on Windows means a TCP table
// lookup each; batches keep the owner from waiting behind every one.
func httpChurnLatency(t *testing.T, c *client, owner, other actor) {
	var session struct{ Token, URL string }
	c.must(t, "session", nil, &session)
	baseMax, baseMedian := ownerLatency(t, owner, session.URL, session.Token)
	exe, _ := os.Executable()
	churn := other.command(exe, "client", "http-churn", session.URL)
	in, err := churn.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := churn.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	churn.Stderr = os.Stderr
	if err := churn.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(out)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP churn running: ") {
		in.Close()
		_ = churn.Wait()
		t.Fatal("churn precondition", line, err)
	}
	loadMax, loadMedian := ownerLatency(t, owner, session.URL, session.Token)
	in.Close()
	total, _ := reader.ReadString('\n')
	if err := churn.Wait(); err != nil {
		t.Fatal(err)
	}
	var connections int
	if _, err := fmt.Sscanf(strings.TrimSpace(total), "HTTP churn total=%d", &connections); err != nil || connections < 500 {
		t.Fatal("churn did not load admission", total, err)
	}
	t.Logf("HTTP_CHURN connections=%d owner_latency_idle max=%dms median=%dms under_churn max=%dms median=%dms", connections, baseMax, baseMedian, loadMax, loadMedian)
	if loadMax > 2000 || loadMedian > 500 {
		t.Fatalf("owner HTTP latency under churn: max=%dms median=%dms", loadMax, loadMedian)
	}
}

func httpCapacity(t *testing.T, c *client, owner, other actor) {
	var session struct{ Token, URL string }
	c.must(t, "session", nil, &session)
	exe, _ := os.Executable()
	attack := other.command(exe, "client", "http-flood", session.URL)
	in, err := attack.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := attack.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	attack.Stderr = os.Stderr
	if err := attack.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); _ = attack.Wait() }()
	reader := bufio.NewReader(out)
	line, err := reader.ReadString('\n')
	var held, refused int
	if err != nil {
		t.Fatal("HTTP attack precondition", line, err)
	}
	if _, err := fmt.Sscanf(line, "HTTP attack handles held=%d refused=%d", &held, &refused); err != nil {
		t.Fatal("HTTP attack precondition", line, err)
	}
	// One user gets at most two public HTTP slots.
	if held < 1 || held > 2 || refused < 62 {
		t.Fatalf("HTTP per-user cap not enforced: held=%d refused=%d", held, refused)
	}
	started := time.Now()
	status, body := apiAs(t, owner, session.URL, session.Token, "GET", "/api/state", "")
	if status != 200 {
		t.Fatal("owner starved by HTTP flood", status, string(body))
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("owner HTTP access exceeded 5s during flood")
	}
	line, err = reader.ReadString('\n')
	var closed, open int
	var after string
	if err != nil {
		t.Fatal("header deadline result", err)
	}
	if _, err := fmt.Sscanf(line, "HTTP header deadline closed=%d open=%d after=%s", &closed, &open, &after); err != nil || closed != held || open != 0 {
		t.Fatalf("partial headers outlived the header deadline: %q %v", line, err)
	}
	t.Logf("other user held %d of 64 partial-header connections (%d refused at admission); the server closed the held ones by the header deadline (%s); the owner request succeeded meanwhile", held, refused, after)
}

type httpInput struct{ URL, Token, Method, Route, Body string }
type httpOutput struct {
	Status int
	Body   []byte
}

func httpClientMain() int {
	var input httpInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return 2
	}
	req, err := http.NewRequest(input.Method, input.URL+strings.TrimPrefix(input.Route, "/"), strings.NewReader(input.Body))
	if err != nil {
		return 2
	}
	req.Header.Set("X-Token", input.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 1
	}
	if json.NewEncoder(os.Stdout).Encode(httpOutput{resp.StatusCode, body}) != nil {
		return 1
	}
	return 0
}
func apiAs(t *testing.T, user actor, url, token, method, route, body string) (int, []byte) {
	t.Helper()
	exe, _ := os.Executable()
	cmd := user.command(exe, "client", "http")
	input, _ := json.Marshal(httpInput{url, token, method, route, body})
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("user HTTP", err, string(output))
	}
	var response httpOutput
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatal(err, string(output))
	}
	return response.Status, response.Body
}
