//go:build windows

package winengine

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime/trace"
)

// Hosted-only diagnostics. Timings from these runs include tracing overhead
// and cannot qualify the ordinary routing-on/off comparison.
func startStopTrace(ctx context.Context) func() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("NETSWITCH_ENGINE_STOP_TRACE") != "1" {
		return func() {}
	}
	file, err := os.CreateTemp(filepath.Join("dist", "windows-lifecycle"), "engine-stop-*.trace")
	if err != nil {
		log.Printf("Windows stop trace unavailable: %v", err)
		return func() {}
	}
	if err := trace.Start(file); err != nil {
		file.Close()
		log.Printf("Windows stop trace unavailable: %v", err)
		return func() {}
	}
	log.Printf("Windows stop scheduler trace: %s", file.Name())
	region := trace.StartRegion(ctx, "Windows engine stop")
	return func() {
		region.End()
		trace.Stop()
		if err := file.Close(); err != nil {
			log.Printf("Windows stop trace close: %v", err)
		}
	}
}
