//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type ruleView struct {
	rule  netlink.Rule
	extra map[uint16]string
}

// v1.3.1's RuleList omits the fib-rule action and assumes four bytes for
// FRA_IP_PROTO (the UAPI field is one byte). Read these messages through the
// same library's netlink transport, preserving every unknown selector so a
// newer kernel's rule can never compare equal to one of ours by accident.
func readRules(ctx context.Context, family int) ([]ruleView, error) {
	return retryDump(ctx, func() ([]ruleView, error) {
		req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
		msg := nl.NewRtMsg()
		msg.Family = uint8(family)
		req.AddData(msg)
		messages, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
		if err != nil {
			return nil, err
		}
		out := make([]ruleView, 0, len(messages))
		for _, b := range messages {
			v, err := parseRule(b)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	})
}
func parseRule(b []byte) (ruleView, error) {
	v := ruleView{rule: *netlink.NewRule(), extra: map[uint16]string{}}
	if len(b) < 12 {
		return v, errors.New("short fib_rule_hdr")
	}
	r := &v.rule
	r.Family = int(b[0])
	r.Tos = uint(b[3])
	r.Table = int(b[4])
	r.Type = b[7]
	r.Priority = 0
	flags := binary.NativeEndian.Uint32(b[8:])
	r.Invert = flags&2 != 0
	if flags&^uint32(2) != 0 {
		v.extra[65535] = hex.EncodeToString(b[8:12])
	}
	for off := 12; off+4 <= len(b); {
		n := int(binary.NativeEndian.Uint16(b[off:]))
		kind := binary.NativeEndian.Uint16(b[off+2:]) & 0x3fff
		if n < 4 || off+n > len(b) {
			return v, errors.New("invalid fib rule attribute")
		}
		a := b[off+4 : off+n]
		if kind == 1 || kind == 2 {
			bits := int(b[1])
			if kind == 2 {
				bits = int(b[2])
			}
			if len(a) != 4 && len(a) != 16 {
				return v, errors.New("invalid rule address")
			}
			addr := &net.IPNet{IP: net.IP(append([]byte(nil), a...)), Mask: net.CIDRMask(bits, len(a)*8)}
			if kind == 1 {
				r.Dst = addr
			} else {
				r.Src = addr
			}
		} else if kind == 3 || kind == 17 {
			name := strings.TrimRight(string(a), "\x00")
			if kind == 3 {
				r.IifName = name
			} else {
				r.OifName = name
			}
		} else if kind == 21 || kind == 22 {
			if len(a) != 1 {
				return v, errors.New("invalid byte rule attribute")
			}
			if kind == 21 {
				r.Protocol = a[0]
			} else {
				r.IPProto = int(a[0])
			}
		} else if kind == 18 {
			// Alignment padding has no selector semantics.
		} else if kind == 12 && len(a) == 8 {
			r.TunID = uint(binary.NativeEndian.Uint64(a))
		} else if kind == 20 && len(a) == 8 {
			r.UIDRange = netlink.NewRuleUIDRange(binary.NativeEndian.Uint32(a), binary.NativeEndian.Uint32(a[4:]))
		} else if (kind == 23 || kind == 24) && len(a) == 4 {
			ports := netlink.NewRulePortRange(binary.NativeEndian.Uint16(a), binary.NativeEndian.Uint16(a[2:]))
			if kind == 23 {
				r.Sport = ports
			} else {
				r.Dport = ports
			}
		} else if len(a) == 4 {
			x := binary.NativeEndian.Uint32(a)
			switch kind {
			case 4:
				r.Goto = int(x)
			case 6:
				r.Priority = int(x)
			case 10:
				r.Mark = x
			case 11:
				r.Flow = int(x)
			case 13:
				r.SuppressIfgroup = int(int32(x))
			case 14:
				r.SuppressPrefixlen = int(int32(x))
			case 15:
				r.Table = int(x)
			case 16:
				r.Mask = &x
			default:
				v.extra[kind] = hex.EncodeToString(a)
			}
		} else {
			v.extra[kind] = hex.EncodeToString(a)
		}
		off += (n + 3) &^ 3
	}
	return v, nil
}
