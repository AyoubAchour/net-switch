package service

import (
	"net"
	"os"
	"time"
)

// Only the native host's supervision loop calls this after real progress.
// There is deliberately no free-running notification goroutine.
func SupervisionProgress() {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" || os.Getenv("WATCHDOG_USEC") == "" {
		return
	}
	c, err := net.DialTimeout("unixgram", address, 250*time.Millisecond)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	c.Write([]byte("WATCHDOG=1"))
}
