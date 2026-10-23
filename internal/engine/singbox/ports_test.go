package singbox

import (
	"errors"
	"net"
	"testing"
)

type portReservation struct {
	port   int
	closed bool
}

func (p *portReservation) Accept() (net.Conn, error) { panic("reservation must never accept") }
func (p *portReservation) Close() error              { p.closed = true; return nil }
func (p *portReservation) Addr() net.Addr            { return &net.TCPAddr{Port: p.port} }

func TestListenerPortsReservedTogether(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		var reservations []*portReservation
		listen := func() (net.Listener, error) {
			port := 38287
			for _, p := range reservations {
				if !p.closed {
					port++
				}
			}
			p := &portReservation{port: port}
			reservations = append(reservations, p)
			return p, nil
		}
		// Reproduce the old algorithm: a newly freed port is valid for reuse.
		one, _ := listen()
		one.Close()
		two, _ := listen()
		two.Close()
		if one.Addr().String() != two.Addr().String() {
			t.Fatal("fixture did not reproduce reuse")
		}
		api, port, err := reservePorts(proxy, listen)
		if err != nil || api != 38287 || proxy && port != 38288 || !proxy && port != 0 {
			t.Fatal(api, port, err)
		}
		for _, p := range reservations {
			if !p.closed {
				t.Fatal("reservation leaked")
			}
		}
	}
}
func TestSecondReservationFailureClosesFirst(t *testing.T) {
	p := &portReservation{port: 38287}
	calls := 0
	_, _, err := reservePorts(true, func() (net.Listener, error) {
		calls++
		if calls == 1 {
			return p, nil
		}
		return nil, errors.New("exhausted")
	})
	if err == nil || !p.closed || calls != 2 {
		t.Fatal("allocation failure was hidden or leaked", err)
	}
}
