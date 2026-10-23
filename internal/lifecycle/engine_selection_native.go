//go:build m4_native

package lifecycle

// This explicit build is for the pre-cutover installed-service qualification.
// There is no runtime selector or fallback; the cutover removes this build tag.
const nativeEngineBuild = true

var engineProgram = nativeEngineService
