package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/netip"
	"testing"
)

func TestSTUNRoundTrip(t *testing.T) {
	txid := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := STUNRequest(txid)
	got, err := ParseSTUNRequest(req)
	if err != nil || got != txid {
		t.Fatalf("request round trip: %v %v", got, err)
	}
	for _, mapped := range []string{"203.0.113.2:40000", "[2001:db8:c::2]:5353"} {
		ap := netip.MustParseAddrPort(mapped)
		back, err := ParseSTUNResponse(STUNResponse(txid, ap), txid)
		if err != nil || back != ap {
			t.Errorf("%s came back as %s (%v)", ap, back, err)
		}
	}
	other := txid
	other[0] = 99
	if _, err := ParseSTUNResponse(STUNResponse(txid, netip.MustParseAddrPort("192.0.2.1:1")), other); err == nil {
		t.Error("a response for another transaction must be rejected")
	}
	if _, err := ParseSTUNRequest([]byte("poke")); err == nil {
		t.Error("garbage must not parse as a request")
	}
}

// RFC 5769 section 2.2's sample IPv4 response, so the encoding matches real
// STUN and not just itself.
func TestSTUNKnownAnswer(t *testing.T) {
	txid := [12]byte{0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae}
	msg := STUNResponse(txid, netip.MustParseAddrPort("192.0.2.1:32853"))
	want := []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43}
	if !bytes.Equal(msg[20:], want) {
		t.Fatalf("XOR-MAPPED-ADDRESS = %x, want %x", msg[20:], want)
	}
}

func TestDNS(t *testing.T) {
	src4 := netip.MustParseAddr("192.0.2.2")
	src6 := netip.MustParseAddr("2001:db8:b::2")
	ask := func(name string, qtype uint16, edns uint16, src netip.Addr, max int) DNSResult {
		t.Helper()
		query, err := BuildDNSQuery(0x1234, name, qtype, edns)
		if err != nil {
			t.Fatal(err)
		}
		q, err := ParseDNSQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		if q.EDNS != edns {
			t.Fatalf("EDNS %d read as %d", edns, q.EDNS)
		}
		res, err := ParseDNSAnswer(DNSAnswer(q, src, max), 0x1234)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := ask("whoami.test", DNSTypeA, 0, src4, 512); len(res.Addresses) != 1 || res.Addresses[0] != "192.0.2.2" {
		t.Errorf("whoami A: %+v", res)
	}
	if res := ask("WhoAmI.test.", DNSTypeAAAA, 0, src6, 512); len(res.Addresses) != 1 || res.Addresses[0] != "2001:db8:b::2" {
		t.Errorf("whoami AAAA: %+v", res)
	}
	if res := ask("mid.test", DNSTypeTXT, 4096, src4, 4096); res.Truncated || res.TXTBytes != MidTXTBytes || res.Size <= 1280 {
		t.Errorf("mid TXT over EDNS 4096 should be one %d-byte answer over 1280 bytes: %+v", MidTXTBytes, res)
	}
	if res := ask("big.test", DNSTypeTXT, 1232, src4, 1232); !res.Truncated || res.TXTBytes != 0 {
		t.Errorf("big TXT over UDP 1232 should be truncated: %+v", res)
	}
	if res := ask("big.test", DNSTypeTXT, 0, src4, 0); res.Truncated || res.TXTBytes != BigTXTBytes {
		t.Errorf("big TXT over TCP should be whole: %+v", res)
	}
	if res := ask("nothing.test", DNSTypeA, 0, src4, 512); res.Rcode != RcodeNXDomain {
		t.Errorf("unknown names are NXDOMAIN: %+v", res)
	}
}

func TestPatternAndEcho(t *testing.T) {
	data, err := io.ReadAll(Pattern(100_000))
	if err != nil || len(data) != 100_000 {
		t.Fatalf("pattern: %d bytes, %v", len(data), err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != PatternSHA256(100_000) {
		t.Fatal("PatternSHA256 disagrees with Pattern")
	}
	if PatternSHA256(100_000) == PatternSHA256(100_001) {
		t.Fatal("different sizes must give different data")
	}
	src := netip.MustParseAddrPort("192.0.2.1:40000")
	seen, payload, err := ParseEchoReply(EchoReply(src, []byte("T:abc 1")))
	if err != nil || seen != src || string(payload) != "T:abc 1" {
		t.Fatalf("echo round trip: %v %q %v", seen, payload, err)
	}
	if verb, n, err := ParseBulkRequest("GET 1048576"); err != nil || verb != "GET" || n != 1<<20 {
		t.Fatalf("bulk request: %s %d %v", verb, n, err)
	}
	if _, _, err := ParseBulkRequest("DELETE 1"); err == nil {
		t.Fatal("unknown bulk verbs must be rejected")
	}
}
