//go:build linux

package linux

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
)

func (p *Platform) Probe(ctx context.Context, line, operator string) (platform.ProbeResult, error) {
	started := time.Now()
	quick := strings.HasPrefix(operator, "quick:")
	operator = strings.TrimPrefix(operator, "quick:")
	operator = strings.ToLower(operator)
	var url, media, ip string
	switch strings.ToLower(operator) {
	case "cloudflare":
		ip = "1.1.1.1"
		url = "https://1.1.1.1/cdn-cgi/trace"
		media = "text/plain"
	case "google":
		ip = "8.8.8.8"
		url = "https://8.8.8.8/resolve?name=example.com&type=A"
		media = "application/json"
	case "quad9":
		ip = "9.9.9.9"
		media = "application/dns-message"
		query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
		url = "https://9.9.9.9/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(query)
	default:
		return platform.ProbeResult{}, errors.New("unknown probe operator")
	}
	duration := 10 * time.Second
	if quick {
		duration = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	result := func(ok bool, err error) (platform.ProbeResult, error) {
		r := platform.ProbeResult{OK: ok, Latency: time.Since(started)}
		if err != nil {
			r.Error = err.Error()
		}
		return r, nil
	}
	if quick {
		c, err := p.DialTCP(ctx, line, netip.MustParseAddrPort(ip+":443"))
		if err != nil {
			return result(false, err)
		}
		c.Close()
		return result(true, nil)
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		return p.DialTCP(ctx, line, dst)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	typeName, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	ok := resp.StatusCode == 200 && typeName == media && len(body) <= 16384
	switch operator {
	case "cloudflare":
		ok = ok && strings.Contains(string(body), "ip=")
	case "google":
		var answer struct{ Status *int }
		ok = ok && json.Unmarshal(body, &answer) == nil && answer.Status != nil && *answer.Status == 0
	case "quad9":
		ok = ok && resp.ProtoMajor == 2 && len(body) >= 12
	}
	if !ok {
		return result(false, errors.New("HTTPS probe response did not match the operator's success contract"))
	}
	return result(true, nil)
}
