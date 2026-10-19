//go:build linux

package topo

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Snapshot is the PC's routing state: everything an engine might create or
// leave behind. Sections are compared as sets of lines.
type Snapshot map[string][]string

var snapshotSections = []struct {
	name string
	argv []string
}{
	{"ip -4 rule", []string{"ip", "-n", DUT, "-4", "rule", "show"}},
	{"ip -6 rule", []string{"ip", "-n", DUT, "-6", "rule", "show"}},
	{"ip -4 route table all", []string{"ip", "-n", DUT, "-4", "route", "show", "table", "all"}},
	{"ip -6 route table all", []string{"ip", "-n", DUT, "-6", "route", "show", "table", "all"}},
	{"nft ruleset", []string{"ip", "netns", "exec", DUT, "nft", "list", "ruleset"}},
	{"links", []string{"ip", "-n", DUT, "-o", "link", "show"}},
	{"addresses", []string{"ip", "-n", DUT, "-o", "addr", "show"}},
}

// Snapshot reads the PC's routing state.
func (n *Net) Snapshot(ctx context.Context) (Snapshot, error) {
	s := Snapshot{}
	for _, section := range snapshotSections {
		out, err := n.R.Run(ctx, section.argv[0], section.argv[1:]...)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, line := range strings.Split(out, "\n") {
			if line = normalise(section.name, line); line != "" {
				lines = append(lines, line)
			}
		}
		sort.Strings(lines)
		s[section.name] = lines
	}
	return s, nil
}

// normalise drops what changes without anyone changing the configuration:
// counters, link state words and lifetimes.
func normalise(section, line string) string {
	line = strings.TrimSpace(line)
	switch section {
	case "links":
		// "3: eth-a@if2: <BROADCAST,...> mtu 1500 ... state UP ..." -> name and type
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ""
		}
		name := strings.TrimSuffix(fields[1], ":")
		if at := strings.IndexByte(name, '@'); at >= 0 {
			name = name[:at]
		}
		kind := ""
		for i, f := range fields {
			if f == "link/ether" || f == "link/none" || f == "link/loopback" {
				kind = f
			}
			if f == "mtu" && i+1 < len(fields) {
				kind += " mtu " + fields[i+1]
			}
		}
		return name + " " + kind
	case "addresses":
		// "2: eth-a    inet 192.168.1.2/24 scope global eth-a\       valid_lft forever ..."
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return ""
		}
		return fields[1] + " " + fields[2] + " " + fields[3]
	}
	for _, noise := range []string{" linkdown", " dead", " offload", " trap"} {
		line = strings.ReplaceAll(line, noise, "")
	}
	if strings.Contains(line, " cache") || strings.Contains(line, "expires") {
		return ""
	}
	return line
}

// Diff lists what differs from before, per section: "+" lines are new, "-"
// lines are gone. Empty when the states match.
func (s Snapshot) Diff(before Snapshot) []string {
	seen := map[string]bool{}
	var names []string
	for _, snap := range []Snapshot{s, before} {
		for name := range snap {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	var out []string
	for _, name := range names {
		count := map[string]int{}
		for _, line := range before[name] {
			count[line]--
		}
		for _, line := range s[name] {
			count[line]++
		}
		lines := make([]string, 0, len(count))
		for line := range count {
			lines = append(lines, line)
		}
		sort.Strings(lines)
		for _, line := range lines {
			for c := count[line]; c > 0; c-- {
				out = append(out, fmt.Sprintf("%s: + %s", name, line))
			}
			for c := count[line]; c < 0; c++ {
				out = append(out, fmt.Sprintf("%s: - %s", name, line))
			}
		}
	}
	return out
}

// Has reports whether a section contains a line.
func (s Snapshot) Has(section, line string) bool {
	for _, l := range s[section] {
		if l == line {
			return true
		}
	}
	return false
}

// Write saves the snapshot as text, for the case's folder.
func (s Snapshot) Write(path string) error {
	var b strings.Builder
	names := make([]string, 0, len(s))
	for name := range s {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "## %s\n%s\n\n", name, strings.Join(s[name], "\n"))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
