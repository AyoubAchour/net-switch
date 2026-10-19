package jsvalue

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
)

// Marshal retains custom ordered objects and uses JSON.stringify's numeric
// rules: non-finite numbers become null, and negative zero becomes zero.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(jsonValue(v)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
func jsonValue(v any) any {
	if _, ok := v.(json.Marshaler); ok {
		return v
	}
	if v == nil {
		return nil
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Float32, reflect.Float64:
		n := r.Float()
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil
		}
		if n == 0 {
			return float64(0)
		}
		return n
	case reflect.Map:
		if r.Type().Key().Kind() != reflect.String {
			return v
		}
		out := map[string]any{}
		for _, k := range r.MapKeys() {
			out[k.String()] = jsonValue(r.MapIndex(k).Interface())
		}
		return out
	case reflect.Slice, reflect.Array:
		if r.Kind() == reflect.Slice && r.IsNil() {
			return nil
		}
		out := make([]any, r.Len())
		for i := range out {
			out[i] = jsonValue(r.Index(i).Interface())
		}
		return out
	}
	return v
}

// Decode accepts JSON numeric overflow just as JSON.parse does.
func Decode(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return numbers(v), nil
}
func numbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, _ := x.Float64()
		return n
	case []any:
		for i := range x {
			x[i] = numbers(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = numbers(x[k])
		}
	}
	return v
}
