package localipc

import (
	"golang.org/x/sys/windows"
	"os"
	"testing"
)

func TestTCPProcessMustPredateConnection(t *testing.T) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	at := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if _, err := processPeerAt(uint32(os.Getpid()), at-1); err == nil {
		t.Fatal("reused process identity accepted")
	}
	if _, err := processPeerAt(uint32(os.Getpid()), at); err != nil {
		t.Fatal("same-tick legitimate identity refused", err)
	}
}
