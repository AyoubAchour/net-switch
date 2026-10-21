//go:build linux

package app

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

type UDPReplyResult struct {
	Token   string          `json:"token"`
	Replies []UDPReplyCheck `json:"replies"`
}

type UDPReplyCheck struct {
	Sequence int    `json:"sequence"`
	Bytes    int    `json:"bytes"`
	From     string `json:"from"`
	WantHash string `json:"wantHash"`
	Hash     string `json:"hash"`
	Err      string `json:"err"`
	OK       bool   `json:"ok"`
}

func runUDPReply(args []string) (any, error) {
	fs := flag.NewFlagSet("udpreply", flag.ContinueOnError)
	to := fs.String("to", "", "reply server ip:port")
	size := fs.Int("size", 12000, "reply payload bytes")
	count := fs.Int("count", 3, "requests, with no retries")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if len(list) != 1 || *count < 1 || *count > 1000 {
		return nil, usageError{fmt.Errorf("one target and 1..1000 requests required")}
	}
	conn, err := udpSocket(list[0].Addr().Is6(), 0, false)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	r := UDPReplyResult{Token: token()}
	buf := make([]byte, 65536)
	for i := range *count {
		request := wire.UDPReplyRequest(r.Token, *size, i)
		want, err := wire.UDPReplyPayload(request)
		if err != nil {
			return nil, usageError{err}
		}
		check := UDPReplyCheck{Sequence: i, WantHash: fmt.Sprintf("%x", sha256.Sum256(want))}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.WriteToUDPAddrPort([]byte(request), list[0]); err != nil {
			check.Err = Code(err)
		} else {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			check.Bytes, check.Err = n, Code(err)
			if err == nil {
				check.From = netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String()
				check.Hash = fmt.Sprintf("%x", sha256.Sum256(buf[:n]))
				check.OK = n == *size && check.Hash == check.WantHash && check.From == list[0].String()
			}
		}
		r.Replies = append(r.Replies, check)
	}
	return r, nil
}
