package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNativeProbeParity(t *testing.T) {
	for _, tc := range []struct {
		name, target, method, path, media, body string
		custom                                  bool
		code, proto                             int
		pass                                    bool
	}{
		{"custom-error", "192.0.2.1:443", "HEAD", "/", "", "", true, 503, 1, true},
		{"custom-nonstandard-port", "192.0.2.1:8443", "HEAD", "/", "", "", true, 204, 1, true},
		{"custom-overrides-operator", "1.1.1.1:443", "HEAD", "/", "", "", true, 302, 1, true},
		{"cloudflare", "1.1.1.1:443", "GET", "/cdn-cgi/trace", "text/plain", "ip=192.0.2.1", false, 200, 1, true},
		{"portal", "1.1.1.1:443", "GET", "/cdn-cgi/trace", "text/html", "ip=192.0.2.1", false, 200, 1, false},
		{"redirect", "1.1.1.1:443", "GET", "/cdn-cgi/trace", "text/plain", "ip=x", false, 302, 1, false},
		{"google", "8.8.8.8:443", "GET", "/resolve", "application/json", `{"Status":0}`, false, 200, 1, true},
		{"google-missing-status", "8.8.8.8:443", "GET", "/resolve", "application/json", `{}`, false, 200, 1, false},
		{"quad9", "9.9.9.9:443", "GET", "/dns-query", "application/dns-message", "wire", false, 200, 2, true},
		{"quad9-http1", "9.9.9.9:443", "GET", "/dns-query", "application/dns-message", "wire", false, 200, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := https(context.Background(), platform.ProbeRequest{Target: tc.target, Custom: tc.custom}, transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != tc.method || r.URL.Path != tc.path || r.URL.Scheme != "https" {
					t.Fatal(r.Method, r.URL)
				}
				if tc.target == "9.9.9.9:443" && r.Header.Get("Accept") != tc.media {
					t.Fatal("DoH accept missing")
				}
				return &http.Response{StatusCode: tc.code, ProtoMajor: tc.proto, Header: http.Header{"Content-Type": {tc.media}, "Location": {"https://unexpected.invalid/"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			}))
			if (err == nil) != tc.pass || calls != 1 {
				t.Fatal(err, calls)
			}
		})
	}
}

func TestNativeProbeTargetsAndLocalExhaustion(t *testing.T) {
	busy := errors.New("local socket capacity")
	for _, quick := range []bool{true, false} {
		called := 0
		v, err := Run(context.Background(), platform.ProbeRequest{Target: "192.0.2.1:8443", Custom: true, Quick: quick}, Options{
			Unavailable: func(err error) bool { return errors.Is(err, busy) },
			Dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
				called++
				if dst.String() != "192.0.2.1:8443" {
					t.Fatal(dst)
				}
				deadline, ok := ctx.Deadline()
				bound := 10 * time.Second
				if quick {
					bound = 3 * time.Second
				}
				if !ok || time.Until(deadline) > bound {
					t.Error("unbounded probe")
					return nil, errors.New("probe dial lost its deadline")
				}
				return nil, fmt.Errorf("wrapped dial: %w", busy)
			}})
		kind := "full"
		if quick {
			kind = "quick"
		}
		if err != nil || called != 1 || v.OK || v.Outcome != "engineUnavailable" || v.Kind != kind || v.LatencyMS != nil {
			t.Fatal(v, err, called)
		}
	}
	for _, target := range []string{"", "https://example.com/", "example.com:443", "1.1.1.1:0", "[fe80::1%eth0]:443"} {
		if _, err := normalize(platform.ProbeRequest{Target: target}); err == nil {
			t.Fatal("invalid target accepted", target)
		}
	}
	if _, err := normalize(platform.ProbeRequest{Operator: "google", Target: "1.1.1.1:443"}); err == nil {
		t.Fatal("conflicting target accepted")
	}
	for _, op := range []string{"192.0.2.1:8443", "quick:192.0.2.1:8443", "unknown"} {
		if _, err := normalize(platform.ProbeRequest{Operator: op}); err == nil {
			t.Fatal("ambiguous legacy shorthand accepted", op)
		}
	}
	for _, op := range []string{"quick:cloudflare", "quick:google", "quick:quad9"} {
		if r, err := normalize(platform.ProbeRequest{Operator: op}); err != nil || !r.Quick {
			t.Fatal(r, err)
		}
	}
}

func TestProbeWireKindAndMilliseconds(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	o := Options{Elapsed: func() time.Duration { return 23500 * time.Microsecond }, Dial: func(context.Context, netip.AddrPort) (net.Conn, error) { return a, nil }}
	r, err := Run(context.Background(), platform.ProbeRequest{Target: "192.0.2.1:443", Quick: true}, o)
	if err != nil || r.Kind != "quick" || r.LatencyMS == nil || *r.LatencyMS != 23.5 {
		t.Fatal(r, err)
	}
	wire, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(wire), `"latencyMs":23.5`) || strings.Contains(string(wire), `"latency":`) {
		t.Fatal(string(wire), err)
	}
	o.Dial = func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, ErrUnavailable }
	r, err = Run(context.Background(), platform.ProbeRequest{Target: "192.0.2.1:443", Custom: true}, o)
	wire, marshalErr := json.Marshal(r)
	if err != nil || marshalErr != nil || r.Kind != "full" || r.Outcome != "engineUnavailable" || strings.Contains(string(wire), "latency") {
		t.Fatal(string(wire), err, marshalErr)
	}
}
