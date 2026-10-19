package apps

import (
	"bytes"
	"encoding/json"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

// Set replaces an existing property in place, just like assigning a JS key.
func (pins *Pins) Set(path, line string) {
	for i := range *pins {
		if (*pins)[i].Path == path {
			(*pins)[i].LineID = line
			return
		}
	}
	*pins = append(*pins, Pin{path, line})
}

func (pins Pins) MarshalJSON() ([]byte, error) {
	if pins == nil {
		return []byte("null"), nil
	}
	var b bytes.Buffer
	b.WriteByte('{')
	keys := []string{}
	values := map[string]string{}
	for _, pin := range pins {
		if _, ok := values[pin.Path]; !ok {
			keys = append(keys, pin.Path)
		}
		values[pin.Path] = pin.LineID
	}
	for i, key := range objectKeys(keys) {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(js.MarshalString(key))
		b.WriteByte(':')
		b.Write(js.MarshalString(values[key]))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (pins *Pins) UnmarshalJSON(b []byte) error {
	p, err := ParsePins(b)
	if err == nil {
		*pins = p
	}
	return err
}

var _ json.Marshaler = Pins{}
