//go:build !m4_native

package lifecycle

// The production service remains the M2 stand-in until the Control cutover.
const nativeEngineBuild = false

var engineProgram = EngineService
