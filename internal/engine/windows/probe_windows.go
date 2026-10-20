//go:build windows

package winengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
)

func (d *Dialer) Probe(ctx context.Context, line, operator string) (platform.ProbeResult, error) {
	start := winclock.Now()
	if !d.Routes.active.Load() {
		return platform.ProbeResult{Outcome: "engineUnavailable", Error: "routing engine is not running"}, nil
	}
	quick := strings.HasPrefix(operator, "quick:")
	operator = strings.ToLower(strings.TrimPrefix(operator, "quick:"))
	var host, target, media string
	var custom netip.AddrPort
	switch operator {
	case "cloudflare":
		host, target, media = "1.1.1.1", "https://1.1.1.1/cdn-cgi/trace", "text/plain"
	case "google":
		host, target, media = "8.8.8.8", "https://8.8.8.8/resolve?name=example.com&type=A", "application/json"
	case "quad9":
		host, media = "9.9.9.9", "application/dns-message"
		query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
		target = "https://9.9.9.9/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(query)
	default:
		// Today's user-chosen targets are IP:port TCP probes. Keep that
		// contract while named operators provide the full HTTPS checks.
		var err error
		custom, err = netip.ParseAddrPort(operator)
		if err != nil || custom.Port() == 0 {
			return platform.ProbeResult{}, errors.New("unknown probe operator or invalid IP:port target")
		}
		quick = true
	}
	timeout := 10 * time.Second
	if quick {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := func(ok bool, err error) (platform.ProbeResult, error) {
		r := platform.ProbeResult{OK: ok, Outcome: "lineFailed", Latency: winclock.Since(start)}
		if ok {
			r.Outcome = "ok"
		}
		if err != nil {
			r.Error = err.Error()
		}
		return r, nil
	}
	if quick {
		address := custom
		if !address.IsValid() {
			address = netip.MustParseAddrPort(host + ":443")
		}
		c, err := d.DialTCP(ctx, line, address)
		if err != nil {
			return result(false, err)
		}
		c.Close()
		return result(true, nil)
	}
	transport := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			dst, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, err
			}
			return d.DialTCP(ctx, line, dst)
		}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return result(false, err)
	}
	req.Header.Set("Accept", media)
	resp, err := client.Do(req)
	if err != nil {
		return result(false, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil {
		return result(false, err)
	}
	content, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	ok := err == nil && resp.StatusCode == 200 && content == media && len(body) <= 16384
	switch operator {
	case "cloudflare":
		ok = ok && strings.Contains(string(body), "ip=")
	case "google":
		var response struct{ Status *int }
		ok = ok && json.Unmarshal(body, &response) == nil && response.Status != nil && *response.Status == 0
	case "quad9":
		ok = ok && resp.ProtoMajor == 2 && len(body) >= 12
	}
	if !ok {
		return result(false, errors.New("probe did not satisfy the operator's HTTPS contract"))
	}
	return result(true, nil)
}
