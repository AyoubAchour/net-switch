package linecheck

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestExactPassCriteria(t *testing.T) {
	for _, c := range []struct {
		name, target, media, body string
		status, proto             int
		pass                      bool
	}{{"cloudflare", "1.1.1.1:443", "text/plain; charset=utf-8", "ip=192.0.2.1", 200, 1, true}, {"portal", "1.1.1.1:443", "text/html", "ip=anything", 200, 1, false}, {"missing ip", "1.1.1.1:443", "text/plain", "hello", 200, 1, false}, {"google", "8.8.8.8:443", "application/json", `{"Status":0}`, 200, 1, true}, {"missing Status", "8.8.8.8:443", "application/json", `{}`, 200, 1, false}, {"status string", "8.8.8.8:443", "application/json", `{"Status":"0"}`, 200, 1, false}, {"quad9", "9.9.9.9:443", "application/dns-message", "wire", 200, 2, true}, {"http1 refused", "9.9.9.9:443", "application/dns-message", "wire", 200, 1, false}, {"redirect", "1.1.1.1:443", "text/plain", "ip=192.0.2.1", 302, 1, false}} {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			result := HTTPS(context.Background(), c.target, transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if c.target == "9.9.9.9:443" && r.Header.Get("Accept") != "application/dns-message" {
					t.Fatal("wrong DoH accept")
				}
				return &http.Response{StatusCode: c.status, ProtoMajor: c.proto, Header: http.Header{"Content-Type": []string{c.media}, "Location": []string{"https://portal.invalid/"}}, Body: io.NopCloser(strings.NewReader(c.body)), Request: r}, nil
			}))
			if (result.Outcome == engine.OK) != c.pass || calls != 1 {
				t.Fatalf("%+v calls=%d", result, calls)
			}
		})
	}
}

func TestCustomTargetsUseHeadAndAcceptEveryStatusWithoutRedirecting(t *testing.T) {
	for _, code := range []int{200, 204, 301, 302, 404, 500} {
		calls := 0
		result := HTTPS(context.Background(), "1.0.0.1:443", transport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != http.MethodHead || r.URL.String() != "https://1.0.0.1/" {
				t.Fatalf("unexpected custom request: %s %s", r.Method, r.URL)
			}
			return &http.Response{StatusCode: code, Header: http.Header{"Location": []string{"https://portal.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}))
		if result.Outcome != engine.OK || calls != 1 {
			t.Fatalf("HTTP %d: %+v, requests=%d", code, result, calls)
		}
	}
}

func TestExplicitOperatorAddressUsesCustomTargetContract(t *testing.T) {
	result := HTTPS(context.Background(), "1.1.1.1:443", transport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "HEAD" || r.URL.Path != "/" {
			t.Fatalf("custom override became a default operator: %s %s", r.Method, r.URL)
		}
		return &http.Response{StatusCode: 302, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}), true)
	if result.Outcome != engine.OK {
		t.Fatal(result)
	}
}
