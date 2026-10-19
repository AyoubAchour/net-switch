// Package buildinfo holds what a Net Switch 1.0 binary knows about its own
// build. The release build sets Version with -ldflags "-X"; a development
// build reports "dev".
//
// The 1.0 code lives in this root module (cmd/ and internal/). The 0.3.x
// helper keeps its own module in helper/ until 1.0 replaces it.
package buildinfo

// Version is the Net Switch version, set at build time.
var Version = "dev"

// String is the version as shown in logs and the window.
func String() string {
	if Version == "" {
		return "dev"
	}
	return Version
}
