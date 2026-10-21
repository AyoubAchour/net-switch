//go:build windows && !netswitch_handlecheck

package winengine

import "errors"

func startHeapProfile(string, bool) (func() error, error) {
	return func() error { return nil }, nil
}

func CaptureHeapCommand([]string) error {
	return errors.New("heap capture is available only in instrumented hosted-CI builds")
}
