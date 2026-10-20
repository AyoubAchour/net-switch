//go:build !control_test_https

package main

import "github.com/AyoubAchour/net-switch/internal/settings"

// Production builds have no configuration interception.
func controlTestFiles(options settings.Options) settings.Options { return options }
