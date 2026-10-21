// Package singbox drives the baseline engine: sing-box at the version
// packaging/versions.json pins, configured by Net Switch's own generator
// (config.mjs, which calls lib/engine.mjs) and controlled through its Clash
// API, as today's app does.
package singbox

import (
	"encoding/json"
	"fmt"
	controladapter "github.com/AyoubAchour/net-switch/internal/engine/singbox"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// What today's app calls its outbounds and selectors (lib/apps.mjs).
func lineOutbound(id engine.LineID) string { return "line-" + string(id) }
func laneSelector(id engine.LineID) string { return "lane-" + string(id) }

type clashConnections struct {
	Connections []clashConnection `json:"connections"`
}

type clashConnection struct {
	ID       string `json:"id"`
	Metadata struct {
		Network         string `json:"network"`
		SourceIP        string `json:"sourceIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
		ProcessPath     string `json:"processPath"`
	} `json:"metadata"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Start    time.Time `json:"start"`
	Chains   []string  `json:"chains"`
}

// ParseConnections turns the Clash API's /connections into flows.
func ParseConnections(data []byte) ([]engine.Flow, error) {
	var body clashConnections
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, fmt.Errorf("clash /connections: %w", err)
	}
	flows := make([]engine.Flow, 0, len(body.Connections))
	for _, c := range body.Connections {
		f := engine.Flow{
			ID:          c.ID,
			App:         CleanProcessPath(c.Metadata.ProcessPath),
			Protocol:    strings.ToLower(c.Metadata.Network),
			Source:      addrPort(c.Metadata.SourceIP, c.Metadata.SourcePort),
			Destination: addrPort(c.Metadata.DestinationIP, c.Metadata.DestinationPort),
			Started:     c.Start,
			Up:          c.Upload,
			Down:        c.Download,
		}
		// chains[0] is the outbound that carries the flow; a selector it went
		// through comes after it (lib/apps.mjs connectionLine).
		for i, tag := range c.Chains {
			if id, ok := strings.CutPrefix(tag, "line-"); ok && i == 0 {
				f.Line = engine.LineID(id)
			}
			if id, ok := strings.CutPrefix(tag, "lane-"); ok {
				f.Lane = engine.LineID(id)
			}
		}
		if f.Lane == "" {
			f.Lane = f.Line
		}
		flows = append(flows, f)
	}
	return flows, nil
}

func addrPort(ip, port string) netip.AddrPort {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}
	}
	p, _ := strconv.Atoi(port)
	return netip.AddrPortFrom(addr.Unmap(), uint16(p))
}

// CleanProcessPath strips what sing-box and the kernel add to a Linux program
// path: the owner, as in "/opt/x/curl (runner)", then " (deleted)" for a
// program whose file was replaced while it ran.
func CleanProcessPath(p string) string {
	return controladapter.LinuxProcessPath(p)
}

var ruleFlag = regexp.MustCompile(`\[[^\]]*\]`)

// RuleFingerprint is an `ip rule show` line reduced to its fields: the
// kernel's status flags ("[detached]", "[unresolved]") dropped and spaces
// collapsed, so "31102:\tfrom all iif NetSwitch [detached] goto 31110" reads
// "31102: from all iif NetSwitch goto 31110".
func RuleFingerprint(line string) string {
	line = ruleFlag.ReplaceAllString(line, " ")
	pref, rest, ok := strings.Cut(line, ":")
	if !ok {
		return strings.Join(strings.Fields(line), " ")
	}
	return strings.TrimSpace(pref) + ": " + strings.Join(strings.Fields(rest), " ")
}

// Matches reports whether a flow is selected.
func Matches(sel engine.Selector, f engine.Flow) bool {
	switch {
	case len(sel.IDs) > 0:
		for _, id := range sel.IDs {
			if id == f.ID {
				return true
			}
		}
		return false
	case sel.Line != "":
		return f.Line == sel.Line
	case sel.App != "":
		return f.App == sel.App && (sel.NotLine == "" || f.Line != sel.NotLine)
	}
	return false
}
