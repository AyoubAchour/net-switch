package lifecycle_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	for range 64 {
		c, err := net.DialTimeout("tcp4", u.Host, 2*time.Second)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(c, "GET /api/state HTTP/1.1\r\nHost: ")
		held = append(held, c)
	}
	fmt.Println("HTTP attack handles held")
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
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
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "HTTP attack handles held\n" {
		t.Fatal("HTTP attack precondition", line, err)
	}
	started := time.Now()
	status, body := apiAs(t, owner, session.URL, session.Token, "GET", "/api/state", "")
	if status != 200 {
		t.Fatal("owner starved by HTTP flood", status, string(body))
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("owner HTTP access exceeded 5s during flood")
	}
	t.Log("owner HTTP request succeeded while 64 other-user partial-header handles remained open")
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
