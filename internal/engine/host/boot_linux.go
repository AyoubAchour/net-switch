package host

import (
	"errors"
	"os"
	"strings"
)

func CurrentBootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.ReplaceAll(strings.TrimSpace(string(b)), "-", "")
	if !ValidInvocationID(id) {
		return "", errors.New("invalid kernel boot identity")
	}
	return id, nil
}
