//go:build !windows && !linux

package worker

import "fmt"

func Start(string, []string) (Process, error) {
	return nil, fmt.Errorf("restricted OS workers are not implemented on this platform yet")
}
