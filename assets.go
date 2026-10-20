package netswitch

import (
	"embed"
	"encoding/json"
)

// UI contains the unchanged UI used by the Node application and C# tray.
//
//go:embed ui/index.html ui/app.js ui/styles.css ui/favicon.svg
var UI embed.FS

//go:embed package.json
var manifest []byte

func AppVersion() string {
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		panic(err)
	}
	return m.Version
}
