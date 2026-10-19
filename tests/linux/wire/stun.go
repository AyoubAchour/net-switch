package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// The STUN subset: a Binding request, and a Binding success response carrying
// XOR-MAPPED-ADDRESS (RFC 5389 sections 6 and 15.2). That is all a client needs
// to learn the public address and port a server saw.
const (
	stunMagic          = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunXorMapped      = 0x0020
	stunHeaderLen      = 20
)

// STUNRequest builds a Binding request with the given transaction id.
func STUNRequest(txid [12]byte) []byte {
	msg := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(msg[0:], stunBindingRequest)
	binary.BigEndian.PutUint32(msg[4:], stunMagic)
	copy(msg[8:], txid[:])
	return msg
}

// ParseSTUNRequest checks a Binding request and returns its transaction id.
func ParseSTUNRequest(msg []byte) ([12]byte, error) {
	var txid [12]byte
	if len(msg) < stunHeaderLen {
		return txid, errors.New("stun: short message")
	}
	if binary.BigEndian.Uint16(msg[0:]) != stunBindingRequest || binary.BigEndian.Uint32(msg[4:]) != stunMagic {
		return txid, errors.New("stun: not a binding request")
	}
	copy(txid[:], msg[8:20])
	return txid, nil
}

// STUNResponse builds a Binding success response telling the client the
// address it was seen from.
func STUNResponse(txid [12]byte, mapped netip.AddrPort) []byte {
	addr := mapped.Addr().Unmap()
	family, raw := byte(1), addr.AsSlice()
	if addr.Is6() {
		family = 2
	}
	value := make([]byte, 4+len(raw))
	value[1] = family
	binary.BigEndian.PutUint16(value[2:], mapped.Port()^uint16(stunMagic>>16))
	key := xorKey(txid)
	for i := range raw {
		value[4+i] = raw[i] ^ key[i]
	}
	msg := make([]byte, stunHeaderLen, stunHeaderLen+4+len(value))
	binary.BigEndian.PutUint16(msg[0:], stunBindingSuccess)
	binary.BigEndian.PutUint16(msg[2:], uint16(4+len(value)))
	binary.BigEndian.PutUint32(msg[4:], stunMagic)
	copy(msg[8:], txid[:])
	msg = binary.BigEndian.AppendUint16(msg, stunXorMapped)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(value)))
	return append(msg, value...)
}

// ParseSTUNResponse reads the mapped address from a Binding success response
// for the transaction txid.
func ParseSTUNResponse(msg []byte, txid [12]byte) (netip.AddrPort, error) {
	if len(msg) < stunHeaderLen {
		return netip.AddrPort{}, errors.New("stun: short response")
	}
	if binary.BigEndian.Uint16(msg[0:]) != stunBindingSuccess || binary.BigEndian.Uint32(msg[4:]) != stunMagic {
		return netip.AddrPort{}, errors.New("stun: not a binding success response")
	}
	if [12]byte(msg[8:20]) != txid {
		return netip.AddrPort{}, errors.New("stun: response for another transaction")
	}
	length := int(binary.BigEndian.Uint16(msg[2:]))
	if stunHeaderLen+length > len(msg) {
		return netip.AddrPort{}, errors.New("stun: truncated attributes")
	}
	attrs := msg[stunHeaderLen : stunHeaderLen+length]
	key := xorKey(txid)
	for len(attrs) >= 4 {
		kind := binary.BigEndian.Uint16(attrs[0:])
		size := int(binary.BigEndian.Uint16(attrs[2:]))
		if 4+size > len(attrs) {
			return netip.AddrPort{}, errors.New("stun: truncated attribute")
		}
		value := attrs[4 : 4+size]
		if kind == stunXorMapped && size >= 8 {
			port := binary.BigEndian.Uint16(value[2:]) ^ uint16(stunMagic>>16)
			var raw []byte
			switch value[1] {
			case 1:
				raw = make([]byte, 4)
			case 2:
				raw = make([]byte, 16)
			default:
				return netip.AddrPort{}, fmt.Errorf("stun: unknown address family %d", value[1])
			}
			if len(value) < 4+len(raw) {
				return netip.AddrPort{}, errors.New("stun: short address")
			}
			for i := range raw {
				raw[i] = value[4+i] ^ key[i]
			}
			addr, _ := netip.AddrFromSlice(raw)
			return netip.AddrPortFrom(addr, port), nil
		}
		attrs = attrs[4+(size+3)&^3:]
	}
	return netip.AddrPort{}, errors.New("stun: no XOR-MAPPED-ADDRESS")
}

// xorKey is the magic cookie followed by the transaction id: the first 4 bytes
// mask an IPv4 address, all 16 an IPv6 one.
func xorKey(txid [12]byte) [16]byte {
	var key [16]byte
	binary.BigEndian.PutUint32(key[:], stunMagic)
	copy(key[4:], txid[:])
	return key
}
