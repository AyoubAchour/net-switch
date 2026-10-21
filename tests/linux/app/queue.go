//go:build linux

package app

import (
	"flag"
	"net"
	"time"
)

type QueueResult struct {
	Opened, Sent int
	Errors       map[string]int
	Token        string
}

func runUDPQueue(args []string) (any, error) {
	f := flag.NewFlagSet("udpqueue", flag.ContinueOnError)
	to := f.String("to", "", "echo destination")
	sockets := f.Int("sockets", 1, "held sockets")
	packets := f.Int("packets", 100, "datagrams per socket")
	size := f.Int("size", 64, "payload bytes")
	rate := f.Int("rate", 10000, "datagrams per second")
	release := f.String("release-file", "", "hold barrier")
	if err := parse(f, args); err != nil {
		return nil, err
	}
	r := QueueResult{Errors: map[string]int{}, Token: token()}
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	next := time.Now()
	interval := time.Second / time.Duration(max(1, *rate))
	for i := 0; i < *sockets; i++ {
		c, err := net.Dial("udp", *to)
		if err != nil {
			r.Errors[Code(err)]++
			continue
		}
		conns = append(conns, c)
		r.Opened++
		for j := 0; j < *packets; j++ {
			if wait := time.Until(next); wait > 0 {
				time.Sleep(wait)
			}
			next = next.Add(interval)
			_, err := c.Write(payload(r.Token, i, j, *size))
			if err != nil {
				r.Errors[Code(err)]++
			} else {
				r.Sent++
			}
		}
	}
	return holdUntil(*release, r)
}
