package jsvalue

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// A JavaScript slice can end between an emoji's UTF-16 halves. Preserve that
// code unit as WTF-8 internally, then escape it when writing JSON.
func UTF16Slice(text string, limit int) string {
	units := utf16.Encode([]rune(text))
	if len(units) <= limit {
		return text
	}
	units = units[:limit]
	last := units[len(units)-1]
	if last < 0xd800 || last > 0xdbff {
		return string(utf16.Decode(units))
	}
	return string(utf16.Decode(units[:len(units)-1])) + string([]byte{0xe0 | byte(last>>12), 0x80 | byte((last>>6)&63), 0x80 | byte(last&63)})
}

func MarshalString(text string) json.RawMessage {
	var out strings.Builder
	out.WriteByte('"')
	for len(text) > 0 {
		if len(text) >= 3 && text[0] == 0xed && text[1] >= 0xa0 && text[1] <= 0xbf && text[2] >= 0x80 && text[2] <= 0xbf {
			unit := uint16(text[0]&15)<<12 | uint16(text[1]&63)<<6 | uint16(text[2]&63)
			fmt.Fprintf(&out, "\\u%04x", unit)
			text = text[3:]
			continue
		}
		r, size := utf8.DecodeRuneInString(text)
		encoded, _ := Marshal(string(r))
		out.Write(encoded[1 : len(encoded)-1])
		text = text[size:]
	}
	out.WriteByte('"')
	return json.RawMessage(out.String())
}
