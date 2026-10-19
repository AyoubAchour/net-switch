// Command nsquic is the acceptance suites' QUIC fixture: a controlled QUIC v1
// target, and a client that sends a payload through it and reads one back,
// both checked by SHA-256. The Linux and Windows acceptance harnesses run it;
// it's never part of Net Switch.
//
//	nsquic --serve --address 198.51.100.10:4433,[2001:db8::10]:4433 --state ready.json [--records conns.jsonl]
//	nsquic --address 198.51.100.10:4433 --certificate <sha256> [--upload N] [--download N] [--initial-packet-size 1200]
//
// The client prints one JSON result. The target writes its certificate's
// SHA-256 to the state file, and with --records one JSON line per connection:
// who it came from, what it carried, and the largest datagram it received.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("nsquic (acceptance QUIC fixture), quic-go %s, %s %s/%s\n", quicGoVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}
	// It serves on, and binds to, whatever it's told: hosted CI runners only,
	// never a PC whose network matters.
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		log.Fatal("nsquic runs on GitHub-hosted runners only")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func quicGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/quic-go/quic-go" {
				return dep.Version
			}
		}
	}
	return "(unknown)"
}

type options struct {
	serve             bool
	address           string
	source            string
	iface             int
	state             string
	records           string
	certificate       string
	upload, download  int64
	initialPacketSize int
	timeout           time.Duration
}

// limit bounds what one connection may carry either way.
const limit = 64 << 20

func parse(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("nsquic", flag.ContinueOnError)
	f.BoolVar(&o.serve, "serve", false, "run the target")
	f.StringVar(&o.address, "address", "", "serve: addresses to listen on, comma-separated; client: the target")
	f.StringVar(&o.source, "source", "", "client: source address (default: routing decides)")
	f.IntVar(&o.iface, "interface", 0, "bind to this interface index (0: routing decides)")
	f.StringVar(&o.state, "state", "", "serve: write the ready JSON here")
	f.StringVar(&o.records, "records", "", "serve: append one JSON line per connection here")
	f.StringVar(&o.certificate, "certificate", "", "client: the target certificate's SHA-256")
	f.Int64Var(&o.upload, "upload", 1<<20, "client: bytes to send")
	f.Int64Var(&o.download, "download", 0, "client: bytes the target sends back")
	f.IntVar(&o.initialPacketSize, "initial-packet-size", 0, "quic-go's InitialPacketSize, the packet size floor (0: quic-go's default)")
	timeout := f.Int("timeout", 15000, "client: ms for the whole exchange")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	o.timeout = time.Duration(*timeout) * time.Millisecond
	switch {
	case o.address == "":
		return o, errors.New("--address is required")
	case o.serve && o.state == "":
		return o, errors.New("--serve needs --state")
	case !o.serve && len(o.certificate) != 64:
		return o, errors.New("--certificate (a SHA-256 in hex) is required")
	case o.upload < 0 || o.upload > limit || o.download < 0 || o.download > limit:
		return o, fmt.Errorf("--upload and --download take 0 to %d bytes", limit)
	case o.initialPacketSize != 0 && (o.initialPacketSize < 1200 || o.initialPacketSize > 65535):
		return o, errors.New("--initial-packet-size is 0 or at least 1200")
	}
	return o, nil
}

func (o options) quicConfig() *quic.Config {
	return &quic.Config{
		Versions:             []quic.Version{quic.Version1},
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       15 * time.Second,
		InitialPacketSize:    uint16(o.initialPacketSize),
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	if o.serve {
		s, err := listen(ctx, o)
		if err != nil {
			return err
		}
		ready, err := json.Marshal(s.ready())
		if err != nil {
			return err
		}
		if err := os.WriteFile(o.state, ready, 0o600); err != nil {
			return err
		}
		<-ctx.Done()
		return s.close()
	}
	r, err := dial(ctx, o)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(r)
}
