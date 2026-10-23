package flows

// ReferencesLine includes the current policy and resolved admissions, including
// pending dials. Native socket pins separately protect closing tails; retained
// app-facing TIME_WAIT endpoints alone need no physical routing slot.
func (t *Table) ReferencesLine(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return (t.policy != nil && t.policy.HasLine(id)) || t.lineRefs[id] != 0
}
