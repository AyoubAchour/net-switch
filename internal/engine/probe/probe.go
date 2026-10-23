// Package probe shares the native line-check contract between both OSes.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/linecheck"
)

type Options struct {
	Dial        func(context.Context, netip.AddrPort) (net.Conn, error)
	Unavailable func(error) bool
	Elapsed     func() time.Duration
	// TLS is nil in product hosts. Hosted proofs install a private test CA,
	// retaining normal hostname/certificate checks against the real target IP.
	TLS *tls.Config
}

var ErrUnavailable = errors.New("routing engine is not running")

func normalize(r platform.ProbeRequest) (platform.ProbeRequest, error) {
	if r.Target != "" && r.Operator != "" {
		return r, errors.New("choose a probe target or operator")
	}
	if r.Operator != "" {
		r.Quick = r.Quick || strings.HasPrefix(r.Operator, "quick:")
		op := strings.ToLower(strings.TrimPrefix(r.Operator, "quick:"))
		switch op {
		case "cloudflare":
			r.Target = "1.1.1.1:443"
		case "google":
			r.Target = "8.8.8.8:443"
		case "quad9":
			r.Target = "9.9.9.9:443"
		default:
			return r, errors.New("unknown probe operator; custom checks require target and explicit quick/custom options")
		}
	}
	address, err := netip.ParseAddrPort(r.Target)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" {
		return r, errors.New("probe target must be an IP:port")
	}
	r.Target = netip.AddrPortFrom(address.Addr().Unmap(), address.Port()).String()
	return r, nil
}

func Run(ctx context.Context, request platform.ProbeRequest, o Options) (platform.ProbeResult, error) {
	r, err := normalize(request)
	if err != nil {
		return platform.ProbeResult{}, err
	}
	bound := 10 * time.Second
	kind := "full"
	if r.Quick {
		bound = 3 * time.Second
		kind = "quick"
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	started := time.Now()
	if o.Elapsed == nil {
		o.Elapsed = func() time.Duration { return time.Since(started) }
	}
	result := func(err error) (platform.ProbeResult, error) {
		v := platform.ProbeResult{OK: err == nil, Kind: kind, Outcome: "ok"}
		if err != nil {
			v.Outcome, v.Error = "lineFailed", err.Error()
			if errors.Is(err, ErrUnavailable) || errors.Is(err, context.Canceled) || (o.Unavailable != nil && o.Unavailable(err)) {
				v.Outcome = "engineUnavailable"
			}
		} else {
			ms := float64(o.Elapsed()) / float64(time.Millisecond)
			v.LatencyMS = &ms
		}
		return v, nil
	}
	if r.Quick {
		c, err := o.Dial(ctx, netip.MustParseAddrPort(r.Target))
		if err == nil {
			c.Close()
		}
		return result(err)
	}
	if o.TLS != nil {
		o.TLS = o.TLS.Clone()
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, TLSClientConfig: o.TLS,
		DialContext: func(transportContext context.Context, _, address string) (net.Conn, error) {
			dst, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, err
			}
			// net/http detaches request deadlines when starting a reusable dial.
			// A probe must never leave a detached, unbounded socket attempt behind.
			dial, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(transportContext, cancel)
			defer stop()
			defer cancel()
			return o.Dial(dial, dst)
		}}
	defer transport.CloseIdleConnections()
	return result(https(ctx, r, transport))
}

func https(ctx context.Context, r platform.ProbeRequest, transport http.RoundTripper) error {
	e := linecheck.ForTarget(r.Target, r.Custom)
	method := http.MethodGet
	if e.Operator == "custom" {
		method = http.MethodHead
	}
	req, err := http.NewRequestWithContext(ctx, method, e.URL, nil)
	if err != nil {
		return err
	}
	if e.Accept != "" {
		req.Header.Set("Accept", e.Accept)
	}
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if !linecheck.Validate(e, response) {
		return fmt.Errorf("HTTPS response failed %s probe criteria", e.Operator)
	}
	return nil
}
