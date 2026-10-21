package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func adapterIP(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/ip", args...)
	cmd.Env = service.ChildEnvironment()
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("adapter ownership ip %v: %w: %s", args, err, b)
	}
	return string(b), nil
}
func ruleText(line string) string {
	// The kernel adds [detached] after the input interface disappears.
	return strings.Join(strings.Fields(strings.NewReplacer("[detached]", "", "[unresolved]", "").Replace(line)), " ")
}

// These are the kernel fingerprints observed in the pinned adapter's real TUN
// fixture, checked against sing-tun bca4bf029237's Linux rule contract.
// No upstream implementation is linked or copied. This temporary compatibility
// data is retired with sing-box; policy and the native engine do not use it.
func adapterRuleContract(base, table int) map[string][]string {
	target := strconv.Itoa(table)
	end := strconv.Itoa(base + 10)
	line := func(offset int, selector string) string { return fmt.Sprintf("%d: %s", base+offset, selector) }
	return map[string][]string{
		"-4": {
			line(0, "from all to 198.18.0.0/30 lookup "+target),
			line(1, "from all lookup "+target+" suppress_prefixlength 0"),
			line(2, "not from all dport 53 lookup 254 suppress_prefixlength 0"),
			line(2, "from all iif NetSwitch goto "+end),
			line(3, "not from all iif lo lookup "+target),
			line(3, "from 0.0.0.0 iif lo lookup "+target),
			line(3, "from 198.18.0.0/30 iif lo lookup "+target),
			line(10, "from all nop"),
		},
		"-6": {
			line(0, "from all lookup "+target+" suppress_prefixlength 0"),
			line(1, "not from all dport 53 lookup 254 suppress_prefixlength 0"),
			line(1, "from fdfe:dcba:9876::/126 iif lo lookup "+target),
			line(2, "from all iif NetSwitch goto "+end),
			line(2, "from ::/1 iif lo goto "+end),
			line(2, "from 8000::/1 iif lo goto "+end),
			line(3, "from all lookup "+target),
			line(10, "from all nop"),
		},
	}
}

func adapterOwnership(c Config, store *journal.FileStore, boot, instance string) func([]byte) ([]byte, error) {
	if c.Mode != "tun" {
		return nil
	}
	return func(input []byte) ([]byte, error) {
		if _, err := net.InterfaceByName("NetSwitch"); err == nil {
			return nil, errors.New("TUN name is already in use")
		}
		var config map[string]any
		if err := json.Unmarshal(input, &config); err != nil {
			return nil, err
		}
		inbounds, ok := config["inbounds"].([]any)
		if !ok || len(inbounds) != 1 {
			return nil, errors.New("unexpected adapter inbound layout")
		}
		inbound, ok := inbounds[0].(map[string]any)
		if !ok || inbound["type"] != "tun" || inbound["auto_route"] != true || inbound["interface_name"] != "NetSwitch" {
			return nil, errors.New("unrecognized adapter routing contract")
		}
		used := map[int]bool{}
		tables := map[int]bool{}
		for _, family := range []string{"-4", "-6"} {
			text, err := adapterIP("-N", family, "rule", "show")
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(text, "\n") {
				pref, _, ok := strings.Cut(line, ":")
				if ok {
					n, _ := strconv.Atoi(strings.TrimSpace(pref))
					used[n] = true
				}
				fields := strings.Fields(line)
				for i, field := range fields {
					if field == "lookup" && i+1 < len(fields) {
						if table, err := strconv.Atoi(fields[i+1]); err == nil {
							tables[table] = true
						}
					}
				}
			}
		}
		base := 9100
		for ; base < 30000; base += 20 {
			free := true
			for i := base; i <= base+10; i++ {
				free = free && !used[i]
			}
			if free {
				break
			}
		}
		if base >= 30000 {
			return nil, errors.New("no free adapter policy-rule block")
		}
		// A fresh table ensures stale or unrelated routes cannot affect the
		// adapter. Inspect all tables once, then allocate locally.
		for _, family := range []string{"-4", "-6"} {
			text, err := adapterIP("-j", "-N", family, "route", "show", "table", "all")
			if err != nil {
				return nil, err
			}
			var routes []map[string]any
			if err := json.Unmarshal([]byte(text), &routes); err != nil {
				return nil, err
			}
			for _, route := range routes {
				if v, ok := route["table"].(float64); ok {
					tables[int(v)] = true
				}
			}
		}
		table := 3110
		for tables[table] && table < 32000 {
			table++
		}
		if table >= 32000 {
			return nil, errors.New("no free adapter route table")
		}
		for _, family := range []string{"-4", "-6"} {
			for _, rule := range adapterRuleContract(base, table)[family] {
				record := journal.Record{ID: randomID(), Boot: boot, Instance: instance, Kind: "adapter-linux-rule", Phase: "intent", Fingerprint: journal.Fingerprint{"family": family, "rule": rule, "base": strconv.Itoa(base), "table": strconv.Itoa(table)}}
				if err := store.Append(record); err != nil {
					return nil, err
				}
			}
		}
		// All persistent rule intents have reached disk before the child is
		// allowed to create any of them, including a partial-start crash.
		inbound["iproute2_rule_index"] = base
		inbound["iproute2_table_index"] = table
		return json.MarshalIndent(config, "", "  ")
	}
}

func removeAdapterRule(record journal.Record) error {
	f := record.Fingerprint
	base, e1 := strconv.Atoi(f["base"])
	table, e2 := strconv.Atoi(f["table"])
	if e1 != nil || e2 != nil || base < 9100 || base >= 30000 || table < 3110 || table >= 32000 {
		return errors.New("invalid adapter rule allocation")
	}
	valid := false
	for _, expected := range adapterRuleContract(base, table)[f["family"]] {
		valid = valid || expected == f["rule"]
	}
	if !valid {
		return errors.New("unrecognized adapter rule fingerprint")
	}
	boot, err := BootID()
	if err != nil {
		return err
	}
	if record.Boot != boot {
		return nil
	} // Linux rules cannot survive a reboot.
	text, err := adapterIP("-N", f["family"], "rule", "show")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(text, "\n") {
		if ruleText(line) != f["rule"] {
			continue
		}
		priority, selector, _ := strings.Cut(f["rule"], ": ")
		args := append([]string{f["family"], "rule", "del", "pref", priority}, strings.Fields(selector)...)
		_, err := adapterIP(args...)
		return err
	}
	return nil // absent or replaced: never delete by priority alone
}
