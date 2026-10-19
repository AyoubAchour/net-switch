// Package singbox implements the temporary milestone-one engine adapter. No
// sing-box source is linked or copied; it drives the existing executable.
package singbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

type field struct {
	name  string
	value any
}
type object []field

func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := js.Marshal(f.name)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := js.Marshal(f.value)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
func encode(v any, pretty bool) ([]byte, error) {
	b, err := js.Marshal(v)
	if err != nil || !pretty {
		return b, err
	}
	var out bytes.Buffer
	err = json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

var localRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fc00::/7", "fe80::/10", "ff00::/8"}

type ConfigOptions struct {
	Mode      string
	Lines     []lines.Line
	APIPort   int
	APISecret string
	ProxyPort int
	RuleDir   string
	IPv6      bool
}

func RuleTags(items []lines.Line) []string {
	tags := []string{}
	for i, line := range items {
		tags = append(tags, "apps-"+line.ID)
		if i > 0 {
			tags = append(tags, "share-"+line.ID, "cut-"+line.ID)
		}
	}
	return tags
}

// ConfigBytes matches JSON.stringify(config, null, 2), including key order.
func ConfigBytes(o ConfigOptions) ([]byte, error) {
	if len(o.Lines) == 0 {
		return nil, fmt.Errorf("no lines for engine config")
	}
	inbound := object{{"type", "mixed"}, {"tag", "mixed-in"}, {"listen", "127.0.0.1"}, {"listen_port", o.ProxyPort}}
	if o.Mode == "tun" {
		inbound = object{{"type", "tun"}, {"tag", "tun-in"}, {"interface_name", "NetSwitch"}, {"address", []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"}}, {"mtu", 9000}, {"auto_route", true}, {"strict_route", false}, {"route_exclude_address", localRanges}, {"dns_mode", "disabled"}, {"stack", "gvisor"}}
	}
	outbounds, rules, sets := []any{}, []any{}, []any{}
	for _, line := range o.Lines {
		outbounds = append(outbounds, object{{"type", "direct"}, {"tag", apps.LineOutbound(line.ID)}, {"bind_interface", line.Alias}})
	}
	several := len(o.Lines) > 1
	if several {
		for _, line := range o.Lines {
			targets := []string{apps.LineOutbound(line.ID)}
			for _, other := range o.Lines {
				if line.ID != other.ID {
					targets = append(targets, apps.LineOutbound(other.ID))
				}
			}
			outbounds = append(outbounds, object{{"type", "selector"}, {"tag", apps.LaneSelector(line.ID)}, {"outbounds", targets}, {"default", apps.LineOutbound(line.ID)}, {"interrupt_exist_connections", false}})
		}
	}
	to := func(line lines.Line) string {
		if several {
			return apps.LaneSelector(line.ID)
		}
		return apps.LineOutbound(line.ID)
	}
	if o.Mode == "tun" && !o.IPv6 {
		rules = append(rules, object{{"ip_version", 6}, {"action", "reject"}, {"no_drop", true}})
	}
	for _, line := range o.Lines[1:] {
		rules = append(rules, object{{"rule_set", "cut-" + line.ID}, {"action", "reject"}})
	}
	for _, line := range o.Lines {
		rules = append(rules, object{{"rule_set", "apps-" + line.ID}, {"action", "route"}, {"outbound", to(line)}})
	}
	for _, line := range o.Lines[1:] {
		rules = append(rules, object{{"rule_set", "share-" + line.ID}, {"action", "route"}, {"outbound", to(line)}})
	}
	for _, tag := range RuleTags(o.Lines) {
		sets = append(sets, object{{"type", "local"}, {"tag", tag}, {"format", "source"}, {"path", filepath.Join(o.RuleDir, tag+".json")}})
	}
	return encode(object{
		{"log", object{{"level", "warn"}, {"timestamp", true}}},
		{"dns", object{{"servers", []any{object{{"type", "local"}, {"tag", "local"}}}}}},
		{"inbounds", []any{inbound}}, {"outbounds", outbounds},
		{"route", object{{"rules", rules}, {"rule_set", sets}, {"final", to(o.Lines[0])}, {"auto_detect_interface", true}, {"find_process", true}, {"default_domain_resolver", "local"}}},
		{"experimental", object{{"clash_api", object{{"external_controller", fmt.Sprintf("127.0.0.1:%d", o.APIPort)}, {"secret", o.APISecret}}}}},
	}, true)
}

type RuleFile struct {
	Tag   string
	Bytes []byte
}

// RuleFiles preserves pin priority and emits compact share files, like Node.
func RuleFiles(p engine.Policy) ([]RuleFile, error) {
	never := object{{"process_path", []string{`C:\NetSwitch\no-app-selected.exe`}}}
	ports := map[string][]int{}
	if p.Combine {
		ports = lines.AssignPorts(p.Shares)
	}
	order, pins := []string{}, map[string]apps.Pin{}
	for _, pin := range p.AppLines {
		key := apps.AppKey(pin.Path)
		if _, exists := pins[key]; !exists {
			order = append(order, key)
		}
		pins[key] = pin
	}
	result := []RuleFile{}
	add := func(tag string, rule object) error {
		b, err := encode(object{{"version", 3}, {"rules", []any{rule}}}, !strings.HasPrefix(tag, "share-"))
		if err == nil {
			result = append(result, RuleFile{tag, b})
		}
		return err
	}
	for i, line := range p.Lines {
		paths := []string{}
		for _, key := range order {
			if pin := pins[key]; pin.LineID == line.ID {
				paths = append(paths, apppath.Pattern(pin.Path, apppath.Windows))
			}
		}
		appRule := never
		if len(paths) > 0 {
			appRule = object{{"process_path_regex", paths}}
		}
		if err := add("apps-"+line.ID, appRule); err != nil {
			return nil, err
		}
		if i == 0 {
			continue
		}
		share := never
		if own := ports[line.ID]; len(own) > 0 {
			share = object{{"source_port", own}}
		}
		if err := add("share-"+line.ID, share); err != nil {
			return nil, err
		}
		cut := never
		for _, id := range p.Blocked {
			if id == line.ID {
				cut = appRule
			}
		}
		if err := add("cut-"+line.ID, cut); err != nil {
			return nil, err
		}
	}
	return result, nil
}
