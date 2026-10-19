// Package jsvalue contains the JSON coercions retained from the Node settings format.
package jsvalue

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var decimalNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
var radixNumber = regexp.MustCompile(`^0(?:[xX][0-9a-fA-F]+|[bB][01]+|[oO][0-7]+)$`)

func Number(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case float64:
		return x
	case int:
		return float64(x)
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		s := Trim(x)
		if s == "" {
			return 0
		}
		if radixNumber.MatchString(s) {
			n, _ := new(big.Int).SetString(s, 0)
			f, _ := new(big.Float).SetInt(n).Float64()
			return f
		}
		if s != "Infinity" && s != "+Infinity" && s != "-Infinity" && !decimalNumber.MatchString(s) {
			return math.NaN()
		}
		n, e := strconv.ParseFloat(s, 64)
		if e == nil || errors.Is(e, strconv.ErrRange) {
			return n
		}
	case []any:
		if len(x) == 0 {
			return 0
		}
		if len(x) == 1 {
			if x[0] == nil {
				return 0
			}
			return Number(String(x[0]))
		}
	}
	return math.NaN()
}
func Finite(v any) bool { n, ok := v.(float64); return ok && !math.IsNaN(n) && !math.IsInf(n, 0) }
func String(v any) string {
	if v == nil {
		return "null"
	}
	if list, ok := v.([]any); ok {
		parts := make([]string, len(list))
		for i, item := range list {
			if item != nil {
				parts[i] = String(item)
			}
		}
		return strings.Join(parts, ",")
	}
	if _, ok := v.(map[string]any); ok {
		return "[object Object]"
	}
	return fmt.Sprint(v)
}
func Trim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r == '\ufeff' || r != '\u0085' && unicode.IsSpace(r) })
}
func Text(v any) string { s, _ := v.(string); return s }
func Truth(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0 && !math.IsNaN(x)
	}
	return true
}
func Object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func Default(v, fallback any) any {
	if v == nil {
		return fallback
	}
	return v
}
