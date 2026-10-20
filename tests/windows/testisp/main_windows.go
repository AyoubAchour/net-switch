//go:build windows

// TestISP changes networking only on disposable hosted runners.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("TestISP 1 (%s %s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		log.Fatal("TestISP networking is restricted to disposable GitHub-hosted Windows runners")
	}
	if len(os.Args) < 2 {
		log.Fatal("expected serve, probe or recover")
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "probe":
		err = probe(os.Args[2:])
	case "recover":
		err = recoverDevice()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

type counters struct {
	PacketsIn   uint64 `json:"packetsIn"`
	PacketsOut  uint64 `json:"packetsOut"`
	BytesIn     uint64 `json:"bytesIn"`
	BytesOut    uint64 `json:"bytesOut"`
	Connections uint64 `json:"connections"`
	Errors      uint64 `json:"errors"`
	Dropped     uint64 `json:"dropped"`
}

type observations struct {
	sync.Mutex
	TestISP      counters          `json:"testisp"`
	Uplink       counters          `json:"uplink"`
	Destinations map[string]uint64 `json:"destinations"`
	UDPReplies   map[string]uint64 `json:"udpReplies"`
	EchoRequests map[string]uint64 `json:"echoRequests"`
	TCPTrace     []tcpObservation  `json:"tcpTrace"`
}

type gateway struct {
	tcpReuseHook bool
	device       *observedDevice
	stack        *stack.Stack
	diag         diagnostics
	index        int
	uplinkIP     net.IP
	mode         atomic.Int32 // 0 running, 1 paused, 2 dropping
	stats        observations
	targetMu     sync.RWMutex
	targets      map[string]string
	done         chan struct{}
	stop         sync.Once
}

func (g *gateway) close() { g.stop.Do(func() { close(g.done); g.device.Close() }) }

func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	index := f.Int("uplink-index", 0, "real uplink interface index")
	ip := f.String("uplink-ip", "", "real uplink IPv4 address")
	state := f.String("state", "", "write ready state and final counters here")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *index <= 0 || net.ParseIP(*ip).To4() == nil || *state == "" {
		return errors.New("uplink-index, uplink-ip and state are required")
	}
	if _, err := net.InterfaceByName("TestISP"); err == nil {
		return errors.New("refusing to reuse an existing TestISP adapter")
	}
	token := os.Getenv("TESTISP_TOKEN")
	if len(token) < 32 {
		return errors.New("TESTISP_TOKEN must contain at least 32 characters")
	}
	device, err := openDevice()
	if err != nil {
		return err
	}
	g := &gateway{device: device, index: *index, uplinkIP: net.ParseIP(*ip), done: make(chan struct{}), stats: observations{Destinations: make(map[string]uint64)}}
	defer g.close()
	stack, err := g.startStack()
	if err != nil {
		return err
	}
	defer stack.Close()
	go g.heartbeat()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /targets", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Ports []int `json:"ports"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request) != nil || len(request.Ports) > 8 {
			http.Error(w, "bad target ports", 400)
			return
		}
		targets := make(map[string]string)
		for _, port := range request.Ports {
			if port < 1024 || port > 65535 {
				http.Error(w, "invalid port", 400)
				return
			}
			targets[fmt.Sprintf("198.19.128.2:%d", port)] = net.JoinHostPort(g.uplinkIP.String(), fmt.Sprint(port))
			targets[fmt.Sprintf("[2001:db8:198::2]:%d", port)] = net.JoinHostPort(g.uplinkIP.String(), fmt.Sprint(port))
		}
		g.targetMu.Lock()
		g.targets = targets
		g.targetMu.Unlock()
		json.NewEncoder(w).Encode(targets)
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		g.stats.Lock()
		defer g.stats.Unlock()
		json.NewEncoder(w).Encode(&g.stats)
	})
	mux.HandleFunc("GET /diagnostics", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(g.diagnosticSnapshot())
	})
	mux.HandleFunc("POST /mode", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Mode string `json:"mode"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request) != nil {
			http.Error(w, "bad JSON", 400)
			return
		}
		modes := map[string]int32{"running": 0, "pause": 1, "drop": 2}
		mode, ok := modes[request.Mode]
		if !ok {
			http.Error(w, "unknown mode", 400)
			return
		}
		g.mode.Store(mode)
		json.NewEncoder(w).Encode(request)
	})
	mux.HandleFunc("POST /stop", func(w http.ResponseWriter, r *http.Request) { g.close(); fmt.Fprint(w, "{}") })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		log.Printf("control request peer=%s method=%s path=%s", r.RemoteAddr, r.Method, r.URL.Path)
		defer func() { log.Printf("control response peer=%s path=%s elapsed=%s", r.RemoteAddr, r.URL.Path, time.Since(started)) }()
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		mux.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 3 * time.Second}
	go func() {
		if err := server.Serve(controlListener{listener}); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Print(err)
			g.close()
		}
	}()
	adapter, err := net.InterfaceByName("TestISP")
	if err != nil {
		return err
	}
	ready := map[string]any{"pid": os.Getpid(), "index": adapter.Index, "alias": "TestISP", "instanceID": device.adapter.InstanceID(), "session": "internal/wintun", "address": "198.19.0.1", "control": "http://" + listener.Addr().String(), "uplinkIndex": *index, "uplinkIP": *ip, "tcpReuseHook": g.tcpReuseHook}
	if err := writeJSON(*state, ready); err != nil {
		return err
	}
	log.Printf("ready: TestISP index=%d, upstream index=%d address=%s", adapter.Index, *index, *ip)
	<-g.done
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	g.stats.Lock()
	defer g.stats.Unlock()
	return writeJSON(filepath.Join(filepath.Dir(*state), "final-stats.json"), &g.stats)
}

func writeJSON(file string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(b, '\n'), 0600)
}

func probe(args []string) error {
	f := flag.NewFlagSet("probe", flag.ContinueOnError)
	index := f.Int("interface", 0, "explicit interface index")
	source := f.String("source", "", "explicit source IPv4")
	url := f.String("url", "https://1.1.1.1/cdn-cgi/trace", "target")
	timeout := f.Duration("timeout", 5*time.Second, "total deadline")
	if err := f.Parse(args); err != nil {
		return err
	}
	if (*index == 0) != (*source == "") || *index < 0 || (*source != "" && net.ParseIP(*source).To4() == nil) {
		return errors.New("supply both interface and source, or neither for normal Windows routing")
	}
	dialer := &net.Dialer{Timeout: *timeout}
	if *index != 0 {
		dialer = boundDialer(*index, net.ParseIP(*source))
	}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	response, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, body)
	}
	hash := sha256.Sum256(body)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"interface": *index, "source": *source, "status": response.StatusCode, "bytes": len(body), "sha256": hex.EncodeToString(hash[:]), "body": string(body), "elapsedMs": time.Since(start).Milliseconds()})
}
