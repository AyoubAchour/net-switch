//go:build linux

package suite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(25, addQUIC) }

// Real QUIC (5.8): quic-go on both ends (tests/quicfixture), the client an
// app on the PC with quic-go's Linux send path as it is (GSO, ECN, DF and
// path MTU probing), the target on the fake internet. Linux has its own
// segmentation and error-queue paths, so the Windows runs don't cover it.
func addQUIC(r *registry) {
	for _, mtu := range []int{1280, 1400} {
		r.add(fmt.Sprintf("quic.path-%d", mtu),
			fmt.Sprintf("Real QUIC over a %d-byte path, IPv4 and IPv6: a pinned-certificate handshake and 1 MiB each way checked by hash, all over the app's line, no datagram bigger than the path", mtu),
			harness.Parity, "5.3, 5.8", 3*time.Minute, func(e *Env) { quicPath(e, mtu) })
	}
}

// QUICApp is where the harness installs the QUIC fixture as an app; the
// target runs the same program.
const QUICApp = AppsDir + "/quic/nsquic"

// QUICResult is the fixture client's report (tests/quicfixture's Result).
type QUICResult struct {
	Source         string  `json:"source"` // the client as the target saw it
	Bytes          int64   `json:"bytes"`
	SHA256         string  `json:"sha256"`
	Download       int64   `json:"download"`
	DownloadSHA256 string  `json:"downloadSha256"`
	Local          string  `json:"local"`
	Version        string  `json:"version"`
	ALPN           string  `json:"alpn"`
	GSO            bool    `json:"gso"`
	HandshakeMS    float64 `json:"handshakeMs"`
	TotalMS        float64 `json:"totalMs"`
}

// QUICRecord is one connection as the target recorded it
// (tests/quicfixture's Record).
type QUICRecord struct {
	T             int64  `json:"t"`
	Remote        string `json:"remote"`
	Local         string `json:"local"`
	Version       string `json:"version"`
	UploadBytes   int64  `json:"uploadBytes"`
	UploadSHA256  string `json:"uploadSha256"`
	DownloadBytes int64  `json:"downloadBytes"`
	Datagrams     int    `json:"datagrams"`
	MaxDatagram   int    `json:"maxDatagram"`
	Err           string `json:"err"`
}

// quicTarget is the fixture serving on the fake internet for one case.
type quicTarget struct {
	cert    string
	records string
}

// ciEnv passes on what the fixture checks before it runs at all.
func ciEnv() []string {
	return []string{"GITHUB_ACTIONS=" + os.Getenv("GITHUB_ACTIONS"), "RUNNER_ENVIRONMENT=" + os.Getenv("RUNNER_ENVIRONMENT")}
}

func (e *Env) startQUICTarget() quicTarget {
	if e.cfg.QUIC == "" {
		e.T.Fatalf("this run has no QUIC fixture (nsaccept run --quic)")
	}
	state := filepath.Join(e.T.Dir(), "quic-ready.json")
	t := quicTarget{records: filepath.Join(e.T.Dir(), "quic-records.jsonl")}
	addresses := To(topo.Server4, wire.PortQUIC) + "," + To(topo.Server6, wire.PortQUIC)
	bg := e.Start(Run{Program: e.cfg.QUIC, Netns: topo.INET, User: AsRoot, Env: ciEnv(),
		Args: []string{"--serve", "--address", addresses, "--state", state, "--records", t.records}})
	deadline := time.Now().Add(15 * time.Second)
	for {
		if data, err := os.ReadFile(state); err == nil && len(data) > 0 {
			var ready struct {
				Addresses   []string `json:"addresses"`
				Certificate string   `json:"certificate"`
			}
			if err := json.Unmarshal(data, &ready); err != nil || len(ready.Certificate) != 64 || len(ready.Addresses) != 2 {
				e.T.Fatalf("the QUIC target's ready file: %v: %s", err, data)
			}
			t.cert = ready.Certificate
			return t
		}
		if !bg.Running() || time.Now().After(deadline) {
			e.T.Fatalf("the QUIC target didn't come up (running %v): %s", bg.Running(), strings.TrimSpace(bg.stderr.String()))
		}
		e.Sleep(50 * time.Millisecond)
	}
}

// records reads what the target recorded, every line complete.
func (t quicTarget) read(e *Env) []QUICRecord {
	data, err := os.ReadFile(t.records)
	if err != nil && !os.IsNotExist(err) {
		e.T.Fatalf("the QUIC target's records: %v", err)
	}
	var out []QUICRecord
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec QUICRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			e.T.Fatalf("the QUIC target's records: %v: %s", err, line)
		}
		out = append(out, rec)
	}
	return out
}

func quicPath(e *Env, mtu int) {
	target := e.startQUICTarget()
	e.reducedPath(mtu)
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: engine.App{Path: e.cfg.QUIC}, Line: "c"})
	e.StartEngine(cfg)
	const size = 1 << 20
	for _, fam := range []struct {
		name     string
		server   netip.Addr
		overhead int // IP and UDP headers
	}{{"IPv4", topo.Server4, 20 + 8}, {"IPv6", topo.Server6, 40 + 8}} {
		since := time.Now().UnixMilli()
		label := fmt.Sprintf("QUIC over IPv%s on the %d-byte path", strings.TrimPrefix(fam.name, "IPv"), mtu)
		// 1200 is QUIC's minimum datagram size, which every path must carry
		// (RFC 9000 14). quic-go's default first packets are 1280 bytes of
		// payload, which no 1280-byte path carries whatever the engine does.
		out, err := e.TryExec(Run{Program: e.cfg.QUIC, User: AsUser, Env: ciEnv(), Timeout: 90 * time.Second,
			Args: []string{"--address", To(fam.server, wire.PortQUIC), "--certificate", target.cert, "--upload", strconv.Itoa(size), "--download", strconv.Itoa(size),
				"--initial-packet-size", "1200", "--timeout", "60000"}})
		var r QUICResult
		if err == nil {
			err = json.Unmarshal(lastLine(out), &r)
		}
		e.T.Check(err == nil && r.Version == "v1" && r.Bytes == size && r.Download == size,
			"%s: the handshake completed and 1 MiB went each way, checked by SHA-256 at both ends (%s, %d up, %d down, handshake %.0f ms, %v)",
			label, r.Version, r.Bytes, r.Download, r.HandshakeMS, err)
		e.T.Note("%s: quic-go sent with GSO: %v (local %s, %.0f ms in all)", label, r.GSO, r.Local, r.TotalMS)
		// The target's own records: the connection, where it came from and
		// the biggest datagram that reached it.
		var mine []QUICRecord
		deadline := time.Now().Add(15 * time.Second)
		for {
			mine = mine[:0]
			for _, rec := range target.read(e) {
				remote, err := netip.ParseAddrPort(rec.Remote)
				if err != nil {
					e.T.Fatalf("the QUIC target recorded a connection from %q: %v", rec.Remote, err)
				}
				if rec.T >= since && remote.Addr().Unmap().Is4() == fam.server.Is4() {
					mine = append(mine, rec)
				}
			}
			if len(mine) > 0 || time.Now().After(deadline) {
				break
			}
			e.Sleep(100 * time.Millisecond)
		}
		if !e.T.Check(len(mine) == 1, "%s: the target recorded the connection (%d records)", label, len(mine)) {
			continue
		}
		rec := mine[0]
		e.T.Check(topo.LineOfText(rec.Remote) == "c" && topo.LineOfText(r.Source) == "c",
			"%s: the target saw the connection come over line c, the app's line (from %s, line %q)", label, rec.Remote, topo.LineOfText(rec.Remote))
		e.T.Check(rec.Err == "" && rec.UploadBytes == size && rec.UploadSHA256 == r.SHA256 && rec.DownloadBytes == size,
			"%s: the target received the 1 MiB intact and sent 1 MiB back (%d bytes, SHA-256 %s, %d sent, %q)", label, rec.UploadBytes, rec.UploadSHA256, rec.DownloadBytes, rec.Err)
		limit := mtu - fam.overhead
		e.T.Check(rec.Datagrams > 0 && rec.MaxDatagram <= limit,
			"%s: no datagram bigger than the path carries reached the target, so nothing was fragmented on the way (%d datagrams, largest %d bytes, the path carries %d)",
			label, rec.Datagrams, rec.MaxDatagram, limit)
	}
}
