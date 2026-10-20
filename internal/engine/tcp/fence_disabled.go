//go:build close_fence_disabled

package tcp

// CI mutation: leave admission release intact but never enable the gVisor fence.
const localCloseFenceEnabled = false
