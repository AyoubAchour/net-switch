package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// The DNS subset: one question, A/AAAA/TXT answers and an EDNS0 OPT record.
// The fake internet answers:
//
//	whoami.test A / AAAA   the address the query came from
//	mid.test TXT           about 1,400 bytes (fragmented over a 1280 path)
//	big.test TXT           about 3,000 bytes (truncated over UDP, then TCP)
//
// and NXDOMAIN for anything else.
const (
	DNSTypeA    = 1
	DNSTypeTXT  = 16
	DNSTypeAAAA = 28
	dnsTypeOPT  = 41
	dnsClassIN  = 1

	dnsFlagQR = 1 << 15
	dnsFlagAA = 1 << 10
	dnsFlagTC = 1 << 9
	dnsFlagRD = 1 << 8

	RcodeNXDomain = 3
)

// DNSTypeByName maps "A", "AAAA" and "TXT" to their type numbers.
func DNSTypeByName(name string) (uint16, error) {
	switch strings.ToUpper(name) {
	case "A":
		return DNSTypeA, nil
	case "AAAA":
		return DNSTypeAAAA, nil
	case "TXT":
		return DNSTypeTXT, nil
	}
	return 0, fmt.Errorf("unsupported DNS type %q", name)
}

// DNSQuery is a parsed question.
type DNSQuery struct {
	ID    uint16
	Name  string // lower case, without the final dot
	Type  uint16
	EDNS  uint16 // the client's UDP payload size, 0 without EDNS
	Bytes []byte // the question section as sent, for the answer
}

// BuildDNSQuery makes a recursive query for one name; edns > 0 adds an OPT
// record advertising that UDP payload size.
func BuildDNSQuery(id uint16, name string, qtype uint16, edns uint16) ([]byte, error) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], dnsFlagRD)
	binary.BigEndian.PutUint16(msg[4:], 1)
	if edns > 0 {
		binary.BigEndian.PutUint16(msg[10:], 1)
	}
	var err error
	if msg, err = appendName(msg, name); err != nil {
		return nil, err
	}
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	if edns > 0 {
		msg = append(msg, 0) // root name
		msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)
		msg = binary.BigEndian.AppendUint16(msg, edns)
		msg = binary.BigEndian.AppendUint32(msg, 0)
		msg = binary.BigEndian.AppendUint16(msg, 0)
	}
	return msg, nil
}

func appendName(msg []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("bad DNS name %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	return append(msg, 0), nil
}

// readName reads a possibly compressed name at off; it returns the name and
// the offset just after it in the message (not after a pointer's target).
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errors.New("dns: name runs past the message")
		}
		n := int(msg[off])
		switch {
		case n == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case n&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("dns: short pointer")
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 20 {
				return "", 0, errors.New("dns: pointer loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		default:
			if off+1+n > len(msg) {
				return "", 0, errors.New("dns: label runs past the message")
			}
			labels = append(labels, strings.ToLower(string(msg[off+1:off+1+n])))
			off += 1 + n
		}
	}
}

// ParseDNSQuery reads a query from a client.
func ParseDNSQuery(msg []byte) (DNSQuery, error) {
	var q DNSQuery
	if len(msg) < 12 {
		return q, errors.New("dns: short query")
	}
	q.ID = binary.BigEndian.Uint16(msg[0:])
	if binary.BigEndian.Uint16(msg[4:]) != 1 {
		return q, errors.New("dns: want exactly one question")
	}
	name, off, err := readName(msg, 12)
	if err != nil {
		return q, err
	}
	if off+4 > len(msg) {
		return q, errors.New("dns: short question")
	}
	q.Name, q.Type = name, binary.BigEndian.Uint16(msg[off:])
	q.Bytes = append([]byte(nil), msg[12:off+4]...)
	off += 4
	// The additional section may hold an OPT record (after any answers and
	// authority records, which a query doesn't have).
	if binary.BigEndian.Uint16(msg[10:]) > 0 && off+11 <= len(msg) && msg[off] == 0 &&
		binary.BigEndian.Uint16(msg[off+1:]) == dnsTypeOPT {
		q.EDNS = binary.BigEndian.Uint16(msg[off+3:])
	}
	return q, nil
}

// TXT payloads, in 200-byte strings.
func txtStrings(total int) [][]byte {
	var out [][]byte
	for i := 0; total > 0; i++ {
		n := min(200, total)
		chunk := []byte(fmt.Sprintf("%03d:", i) + strings.Repeat("x", n))[:n]
		out = append(out, chunk)
		total -= n
	}
	return out
}

// TXT sizes the fake internet serves.
const (
	MidTXTBytes = 1400
	BigTXTBytes = 3000
)

// DNSAnswer builds the fake internet's answer to q from src. maxSize is the
// largest message the transport allows (0 for TCP: no limit); a bigger answer
// is cut to the question with TC set, as RFC 1035 asks.
func DNSAnswer(q DNSQuery, src netip.Addr, maxSize int) []byte {
	type rr struct {
		kind uint16
		data []byte
	}
	var answers []rr
	rcode := 0
	src = src.Unmap()
	switch {
	case q.Name == "whoami.test" && q.Type == DNSTypeA && src.Is4():
		answers = append(answers, rr{DNSTypeA, src.AsSlice()})
	case q.Name == "whoami.test" && q.Type == DNSTypeAAAA && src.Is6():
		answers = append(answers, rr{DNSTypeAAAA, src.AsSlice()})
	case q.Name == "whoami.test":
		// The name exists; there's just no record of that type.
	case (q.Name == "mid.test" || q.Name == "big.test") && q.Type == DNSTypeTXT:
		size := MidTXTBytes
		if q.Name == "big.test" {
			size = BigTXTBytes
		}
		// One TXT record per string keeps each record well under 64 KiB.
		for _, s := range txtStrings(size) {
			answers = append(answers, rr{DNSTypeTXT, append([]byte{byte(len(s))}, s...)})
		}
	default:
		rcode = RcodeNXDomain
	}
	build := func(withAnswers bool) []byte {
		msg := make([]byte, 12, 512)
		binary.BigEndian.PutUint16(msg[0:], q.ID)
		flags := uint16(dnsFlagQR | dnsFlagAA | dnsFlagRD | rcode)
		if !withAnswers && len(answers) > 0 {
			flags |= dnsFlagTC
		}
		binary.BigEndian.PutUint16(msg[2:], flags)
		binary.BigEndian.PutUint16(msg[4:], 1)
		msg = append(msg, q.Bytes...)
		if withAnswers {
			binary.BigEndian.PutUint16(msg[6:], uint16(len(answers)))
			for _, a := range answers {
				msg = append(msg, 0xC0, 12) // the question's name
				msg = binary.BigEndian.AppendUint16(msg, a.kind)
				msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
				msg = binary.BigEndian.AppendUint32(msg, 60)
				msg = binary.BigEndian.AppendUint16(msg, uint16(len(a.data)))
				msg = append(msg, a.data...)
			}
		}
		return msg
	}
	msg := build(true)
	if maxSize > 0 && len(msg) > maxSize {
		msg = build(false)
	}
	return msg
}

// DNSResult is what a client learns from an answer.
type DNSResult struct {
	Rcode     int      `json:"rcode"`
	Truncated bool     `json:"truncated"`
	Addresses []string `json:"addresses,omitempty"`
	TXTBytes  int      `json:"txtBytes,omitempty"`
	Size      int      `json:"size"`
}

// ParseDNSAnswer reads an answer to the query with the given id.
func ParseDNSAnswer(msg []byte, id uint16) (DNSResult, error) {
	res := DNSResult{Size: len(msg)}
	if len(msg) < 12 {
		return res, errors.New("dns: short answer")
	}
	if binary.BigEndian.Uint16(msg[0:]) != id {
		return res, errors.New("dns: answer for another query")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&dnsFlagQR == 0 {
		return res, errors.New("dns: not an answer")
	}
	res.Rcode = int(flags & 0xF)
	res.Truncated = flags&dnsFlagTC != 0
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for range qd {
		_, next, err := readName(msg, off)
		if err != nil {
			return res, err
		}
		off = next + 4
	}
	for range an {
		_, next, err := readName(msg, off)
		if err != nil {
			return res, err
		}
		if next+10 > len(msg) {
			return res, errors.New("dns: short record")
		}
		kind := binary.BigEndian.Uint16(msg[next:])
		size := int(binary.BigEndian.Uint16(msg[next+8:]))
		data := msg[next+10:]
		if size > len(data) {
			return res, errors.New("dns: record data runs past the message")
		}
		data = data[:size]
		switch kind {
		case DNSTypeA, DNSTypeAAAA:
			if addr, ok := netip.AddrFromSlice(data); ok {
				res.Addresses = append(res.Addresses, addr.String())
			}
		case DNSTypeTXT:
			for len(data) > 0 {
				n := int(data[0])
				if 1+n > len(data) {
					return res, errors.New("dns: bad TXT string")
				}
				res.TXTBytes += n
				data = data[1+n:]
			}
		}
		off = next + 10 + size
	}
	return res, nil
}
