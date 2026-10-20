// Package windowsundo validates the saved Windows settings before any restore.
// It is shared by Control and the one-time machine-folder migration.
package windowsundo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

// Aliases retains Object.entries order, including JS's integer-index ordering.
func Aliases(raw json.RawMessage) []string {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil
	}
	keys := []string{}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil
		}
		name := key.(string)
		if !seen[name] {
			keys = append(keys, name)
			seen[name] = true
		}
	}
	index := func(s string) uint64 {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != s || n == math.MaxUint32 {
			return math.MaxUint64
		}
		return n
	}
	sort.SliceStable(keys, func(i, j int) bool { return index(keys[i]) < index(keys[j]) })
	return keys
}

// Validate matches Node's damaged-record check. Do not discard a bad entry:
// restoring only the others would lose the person's original Windows settings.
func Validate(values map[string]any, aliases []string) error {
	problems := []string{}
	policy := js.Object(values["policy"])
	if policy == nil {
		problems = append(problems, "the policy entry is not an object")
	} else if value, exists := policy["value"]; exists && value != nil {
		n, ok := value.(float64)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n {
			problems = append(problems, "the policy value is not a number")
		}
	}
	metrics := js.Object(values["metrics"])
	if metrics == nil {
		problems = append(problems, "the adapter entries are not an object")
	}
	for _, alias := range aliases {
		rows, ok := metrics[alias].([]any)
		if !ok {
			problems = append(problems, alias+": not a list")
			continue
		}
		for _, row := range rows {
			m := js.Object(row)
			_, auto := m["automatic"].(bool)
			if (m["family"] != "IPv4" && m["family"] != "IPv6") || !auto || !js.Finite(m["metric"]) {
				problems = append(problems, alias+": an unreadable entry")
			}
		}
	}
	if len(problems) != 0 {
		return fmt.Errorf("the Windows undo record is damaged (%s), so nothing was undone; it is kept as it is", strings.Join(problems, "; "))
	}
	return nil
}

// MetricsJSON keeps restoration order across partial saves. New adapters are
// appended explicitly by the caller, rather than going through Go map order.
func MetricsJSON(metrics map[string]any, aliases []string) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	for _, alias := range aliases {
		value, exists := metrics[alias]
		if !exists {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.Write(js.MarshalString(alias))
		b.WriteByte(':')
		data, _ := js.Marshal(value)
		b.Write(data)
	}
	b.WriteByte('}')
	return b.Bytes()
}
