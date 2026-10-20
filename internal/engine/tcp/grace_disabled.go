//go:build close_grace_disabled

package tcp

// Mutation proof only: restore the immediate FIN-only overflow reset.
const closeGraceEnabled = false
