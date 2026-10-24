package lifecycle

// Every product build runs the native engine: the Engine service is the thin
// supervisor host and the native engine is its verified child (spec §3.4).
// There is no build tag and no runtime selector; the M2 stand-in's code stays
// only until the removal PR deletes it with sing-box, and nothing can select it.
const nativeEngineBuild = true

var engineProgram = nativeEngineService
