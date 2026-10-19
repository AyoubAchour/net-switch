// Package linecheck implements the three-operator checks from design 4.5.
// Transport binding belongs to the engine adapter, never to app routing rules.
package linecheck

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

type Endpoint struct {
	URL, Accept string
	Operator    string
	HTTP2       bool
}

// ID=0, recursion desired, one question: example.com IN A. A fixed wire query
// makes the DoH request independent of the machine's DNS configuration.
var dnsQuery = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}

func ForTarget(target string) Endpoint {
	switch target {
	case "1.1.1.1:443":
		return Endpoint{"https://1.1.1.1/cdn-cgi/trace", "", "cloudflare", false}
	case "8.8.8.8:443":
		return Endpoint{"https://8.8.8.8/resolve?name=example.com&type=A", "", "google", false}
	case "9.9.9.9:443":
		return Endpoint{"https://9.9.9.9/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(dnsQuery), "application/dns-message", "quad9", true}
	default:
		return Endpoint{"https://" + strings.TrimSuffix(target, ":443") + "/", "", "custom", false}
	}
}
func Validate(e Endpoint, r *http.Response) bool {
	if r.StatusCode != http.StatusOK {
		return false
	}
	if e.HTTP2 && r.ProtoMajor != 2 {
		return false
	}
	if e.Operator == "custom" {
		return true
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil && e.Operator != "custom" {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if err != nil || len(b) > 64*1024 {
		return false
	}
	switch e.Operator {
	case "cloudflare":
		return media == "text/plain" && strings.Contains(string(b), "ip=")
	case "google":
		if media != "application/json" {
			return false
		}
		var v struct {
			Status *float64 `json:"Status"`
		}
		return json.Unmarshal(b, &v) == nil && v.Status != nil && *v.Status == 0
	case "quad9":
		return media == "application/dns-message"
	case "custom":
		return true
	}
	return false
}
func HTTPS(ctx context.Context, target string, transport http.RoundTripper) engine.ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	e := ForTarget(target)
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := http.NewRequestWithContext(ctx, "GET", e.URL, nil)
	if err != nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	if e.Accept != "" {
		r.Header.Set("Accept", e.Accept)
	}
	start := time.Now()
	response, err := client.Do(r)
	if err != nil {
		return engine.ProbeResult{Outcome: engine.LineFailed}
	}
	defer response.Body.Close()
	if !Validate(e, response) {
		return engine.ProbeResult{Outcome: engine.LineFailed}
	}
	ms := float64(time.Since(start).Microseconds()) / 1000
	return engine.ProbeResult{Outcome: engine.OK, Delay: &ms}
}
func TCP(ctx context.Context, target string, dial func(context.Context, string, string) (net.Conn, error)) engine.ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := dial(ctx, "tcp4", target)
	if err != nil {
		return engine.ProbeResult{Outcome: engine.LineFailed}
	}
	conn.Close()
	ms := float64(time.Since(start).Microseconds()) / 1000
	return engine.ProbeResult{Outcome: engine.OK, Delay: &ms}
}
