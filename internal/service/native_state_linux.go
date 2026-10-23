package service

import (
	"encoding/base64"
	"os"
	"strings"
)

const nativeStateComment = "# NetSwitchNativeState="

func nativeStateDirectory() (string, error) {
	b, err := os.ReadFile("/etc/systemd/system/netswitch-engine.service")
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, nativeStateComment) {
			b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, nativeStateComment))
			return string(b), err
		}
	}
	return "", nil
}

func nativeStateMetadata(data string) string {
	return "\n" + nativeStateComment + base64.RawURLEncoding.EncodeToString([]byte(data)) + "\n"
}
