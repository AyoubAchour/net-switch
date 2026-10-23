package flows

// Refusals counts admission decisions, including a repeated SYN or datagram
// after a rate-limited notice. These are not unique client connection counts.
// Classification happens under the admission lock, using the occupied budget
// at that decision, rather than a later peak or a guessed cause from an error.
type Refusals struct {
	Total, UDP, Handshakes, PerApp, UDPPerApp uint64
	Unknown, UnknownUDP, Policy, Unexplained  uint64
	Accounting                                uint64
}

func (r Refusals) Count() uint64 {
	return r.Total + r.UDP + r.Handshakes + r.PerApp + r.UDPPerApp +
		r.Unknown + r.UnknownUDP + r.Policy + r.Unexplained + r.Accounting
}

func (r Refusals) Sub(before Refusals) Refusals {
	return Refusals{
		Total: r.Total - before.Total, UDP: r.UDP - before.UDP,
		Handshakes: r.Handshakes - before.Handshakes, PerApp: r.PerApp - before.PerApp,
		UDPPerApp: r.UDPPerApp - before.UDPPerApp, Unknown: r.Unknown - before.Unknown,
		UnknownUDP: r.UnknownUDP - before.UnknownUDP, Policy: r.Policy - before.Policy,
		Unexplained: r.Unexplained - before.Unexplained,
		Accounting:  r.Accounting - before.Accounting,
	}
}

func (t *Table) refusal(protocol string) *Refusals {
	t.gauges.Rejected++
	if protocol == "udp" {
		return &t.gauges.RefusedUDP
	}
	return &t.gauges.RefusedTCP
}

// Setup rejection is not a capacity decision, even if a pool happened to
// fill meanwhile. Detailed UDP counters distinguish the underlying failure.
func (f *ticket) RefuseSetup() {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed || f.retired || f.setupRefused {
		return
	}
	f.setupRefused = true
	t.refusal(f.record.Protocol).Unexplained++
}

func (t *Table) refuseBegin(protocol string) {
	r := t.refusal(protocol)
	switch {
	case t.gauges.Flows >= t.limits.Flows:
		r.Total++
	case protocol == "udp" && t.gauges.UDP >= t.limits.UDP:
		r.UDP++
	case protocol == "tcp" && t.gauges.Handshakes >= t.limits.Handshakes:
		r.Handshakes++
	default:
		r.Unexplained++
	}
}

func (t *Table) refuseOwner(protocol, app string) {
	r := t.refusal(protocol)
	c := t.apps[app]
	switch {
	case app == "" && protocol == "udp" && t.gauges.UnknownUDP >= t.limits.UnknownUDP:
		r.UnknownUDP++
	case app == "" && t.gauges.Unknown >= t.limits.Unknown:
		r.Unknown++
	case c.flows >= t.limits.PerApp:
		r.PerApp++
	case protocol == "udp" && c.udp >= t.limits.UDPPerApp:
		r.UDPPerApp++
	default:
		r.Unexplained++
	}
}
