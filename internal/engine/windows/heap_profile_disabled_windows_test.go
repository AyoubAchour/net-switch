//go:build windows && !netswitch_handlecheck

package winengine

import "errors"

func deniedHeapEventClient(string) error {
	return errors.New("heap request event is absent from this build")
}
