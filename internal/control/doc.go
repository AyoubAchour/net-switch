// Package control owns Net Switch's settings, routing policy and HTTP API.
//
// The milestone-one executable uses the current elevated-process model and a
// sing-box adapter. Platform reads and engine operations stay behind injectable
// boundaries so recorded completions can exercise the same core as production.
// Service installation, IPC, leases and ownership journals belong to milestone
// two. The existing Node packaging remains the shipped application until the
// desktop and installer migration is complete.
package control
