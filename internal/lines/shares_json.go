package lines

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// UnmarshalJSON preserves line order across the service boundary. Shares uses
// an ordered object on the wire, just like its existing MarshalJSON method.
func (shares *Shares) UnmarshalJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	open, err := d.Token()
	if err != nil {
		return err
	}
	if open == nil {
		*shares = nil
		return nil
	}
	if open != json.Delim('{') {
		return errors.New("shares must be an object")
	}
	next := Shares{}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		id, ok := key.(string)
		if !ok || seen[id] {
			return errors.New("invalid or duplicate share")
		}
		var value float64
		if err := d.Decode(&value); err != nil {
			return err
		}
		seen[id] = true
		next = append(next, Share{ID: id, Value: value})
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing shares data")
	}
	*shares = next
	return nil
}
