//go:build control_test_https

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

// Compiled only into the Control TUN test executable. The normal executable
// used by routing, native parity and releases has no fixture reader.
type httpsConfigFiles struct{ settings.Files }

func controlTestFiles(options settings.Options) settings.Options {
	options.Files = httpsConfigFiles{options.Files}
	return options
}

func (f httpsConfigFiles) WriteFile(name string, data []byte, mode os.FileMode) error {
	if filepath.Base(name) != "engine-config.json" {
		return f.Files.WriteFile(name, data, mode)
	}
	marker, err := f.Files.ReadFile(filepath.Join(filepath.Dir(name), "test-local-https.json"))
	if os.IsNotExist(err) {
		return f.Files.WriteFile(name, data, mode)
	}
	if err != nil {
		return err
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return fmt.Errorf("local HTTPS fixture requires a disposable hosted runner")
	}
	var config map[string]json.RawMessage
	var route map[string]json.RawMessage
	var rules []json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	if err := json.Unmarshal(config["route"], &route); err != nil {
		return err
	}
	if err := json.Unmarshal(route["rules"], &rules); err != nil {
		return err
	}
	if !json.Valid(marker) {
		return fmt.Errorf("invalid local HTTPS fixture rule")
	}
	if err := f.Files.WriteFile(filepath.Join(filepath.Dir(name), "traffic-product-config.json"), data, mode); err != nil {
		return err
	}
	route["rules"], err = json.Marshal(append([]json.RawMessage{marker}, rules...))
	if err != nil {
		return err
	}
	config["route"], err = json.Marshal(route)
	if err != nil {
		return err
	}
	data, err = json.Marshal(config)
	if err != nil {
		return err
	}
	return f.Files.WriteFile(name, data, mode)
}
