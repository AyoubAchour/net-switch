package lifecycle_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"golang.org/x/sys/windows"
)

func disconnectBurst() error {
	path, _ := windows.UTF16PtrFromString(localipc.DefaultPath("status"))
	var opened atomic.Uint64
	var workers sync.WaitGroup
	end := time.Now().Add(5 * time.Second)
	for range 8 {
		workers.Go(func() {
			for time.Now().Before(end) {
				h, err := windows.CreateFile(path, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
				if err == nil {
					windows.CloseHandle(h)
					opened.Add(1)
				}
			}
		})
	}
	workers.Wait()
	if opened.Load() < 500 {
		return fmt.Errorf("burst only connected %d times", opened.Load())
	}
	fmt.Printf("raw other-user connect/close burst: %d connections\n", opened.Load())
	return nil
}
