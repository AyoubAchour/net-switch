//go:build !windows

package winplatform

import "fmt"

func Execute(operation string, _ map[string]any) (any, error) {
	return nil, fmt.Errorf("%s: Linux platform support is not implemented yet", operation)
}
func Architecture() (string, error) {
	return "", fmt.Errorf("native platform architecture is not implemented on Linux yet")
}
func RunServerTask() error { return fmt.Errorf("startup integration is not implemented on Linux yet") }
func ControlElevated() (bool, error) {
	return false, fmt.Errorf("elevation check is not implemented on Linux yet")
}
func ProgramFiles() (string, error) { return "", fmt.Errorf("Program Files is Windows-only") }
