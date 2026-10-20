//go:build linux

package topo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TrafficSnapshot covers both ends of every veth, the TUN, all router queues,
// and both native TCP endpoints. Times delimit the observation: these separate
// kernel reads are not an atomic packet trace.
type TrafficSnapshot struct {
	Started, Finished time.Time
	Hops              []TrafficHop
}

type TrafficHop struct {
	Namespace                       string
	Links, Qdiscs                   json.RawMessage
	Classes                         map[string]json.RawMessage
	SNMP, Netstat, Softnet, Sockets string
	Errors                          []string `json:",omitempty"`
}

func (n *Net) Traffic(ctx context.Context) (TrafficSnapshot, error) {
	s := TrafficSnapshot{Started: time.Now().UTC()}
	// The caller writes the full snapshot once, rather than duplicating all
	// socket/counter output in the topology command log.
	r := NewRunner(nil)
	var errs []error
	for _, ns := range allNamespaces {
		if ns == CTR {
			if _, err := os.Stat(filepath.Join("/run/netns", ns)); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		h := TrafficHop{Namespace: ns, Classes: map[string]json.RawMessage{}}
		read := func(name string, args ...string) string {
			out, err := r.In(ctx, ns, name, args...)
			if err != nil {
				err = fmt.Errorf("traffic diagnostics %s: %w", ns, err)
				errs = append(errs, err)
				h.Errors = append(h.Errors, err.Error())
			}
			return out
		}
		readJSON := func(name string, args ...string) json.RawMessage {
			out := read(name, args...)
			if !json.Valid([]byte(out)) {
				err := fmt.Errorf("traffic diagnostics %s %s %v: invalid JSON: %s", ns, name, args, out)
				errs = append(errs, err)
				h.Errors = append(h.Errors, err.Error())
				return nil
			}
			return json.RawMessage(out)
		}
		h.Links = readJSON("ip", "-s", "-s", "-j", "-d", "link", "show")
		h.Qdiscs = readJSON("tc", "-s", "-j", "-d", "qdisc", "show")
		var links []struct {
			Name string `json:"ifname"`
		}
		if json.Unmarshal(h.Links, &links) == nil {
			for _, link := range links {
				h.Classes[link.Name] = readJSON("tc", "-s", "-j", "-d", "class", "show", "dev", link.Name)
			}
		}
		h.SNMP = read("cat", "/proc/net/snmp")
		h.Netstat = read("cat", "/proc/net/netstat")
		h.Softnet = read("cat", "/proc/net/softnet_stat")
		h.Sockets = read("ss", "-t", "-i", "-n", "-m", "-o")
		s.Hops = append(s.Hops, h)
	}
	s.Finished = time.Now().UTC()
	return s, errors.Join(errs...)
}
