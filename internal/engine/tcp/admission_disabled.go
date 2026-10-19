//go:build close_admission_disabled

package tcp

// CI mutation: remove close release while retaining the same packet processing.
// This build must fail every immediate-replacement regression in the proof run.
const closeAdmissionEnabled = false
