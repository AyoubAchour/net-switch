package linux

// Called under the engine mutation lock, after OpenTun and Prepare. The
// published binding snapshot keeps the watchdog independent of route checks.
func (p *Platform) ForwardingIndex() int {
	if b := p.bindings.Load(); b != nil {
		return b.tunIndex
	}
	return 0
}
