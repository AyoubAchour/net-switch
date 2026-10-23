//go:build !lifecycle_test

package lifecycle

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func configureNativeProof(string, *host.Options) error                                 { return nil }
func nativeProofExit(string) error                                                     { return nil }
func nativeProofRecovery(string) error                                                 { return nil }
func nativeProofBeforeReady(string) error                                              { return nil }
func nativeProofLogSink(_ context.Context, _ string, report func(string)) func(string) { return report }
