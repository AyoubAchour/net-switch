package lifecycle_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"golang.org/x/sys/windows"
)

func lowPipeClient() error {
	var info [64]uint64
	var size uint32
	if err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&info[0])), uint32(unsafe.Sizeof(info)), &size); err != nil {
		return err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&info[0]))
	if label.Label.Sid.String() != "S-1-16-4096" {
		return errors.New("probe is not low integrity")
	}
	path, _ := windows.UTF16PtrFromString(localipc.DefaultPath("desktop"))
	var held []windows.Handle
	readDenied, zeroDenied := 0, 0
	defer func() {
		for _, h := range held {
			windows.CloseHandle(h)
		}
	}()
	for range 64 {
		h, err := windows.CreateFile(path, windows.FILE_READ_DATA, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			windows.CloseHandle(h)
			return errors.New("low integrity read-only pipe open succeeded")
		}
		if err != windows.ERROR_ACCESS_DENIED && err != windows.ERROR_PIPE_BUSY {
			return err
		}
		if err == windows.ERROR_ACCESS_DENIED {
			readDenied++
		}
		h, err = windows.CreateFile(path, 0, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			held = append(held, h)
		} else if err == windows.ERROR_ACCESS_DENIED {
			zeroDenied++
		} else if err != windows.ERROR_ACCESS_DENIED && err != windows.ERROR_PIPE_BUSY {
			return err
		}
	}
	if readDenied == 0 || zeroDenied+len(held) == 0 {
		return errors.New("pipe busy responses did not prove integrity enforcement")
	}
	fmt.Printf("low integrity access checked: read_denied=%d zero_denied=%d zero_held=%d\n", readDenied, zeroDenied, len(held))
	_, err := io.Copy(io.Discard, os.Stdin)
	return err
}

func lowIntegrityCapacity(t *testing.T, owner actor) {
	a := owner.(*windowsActor)
	var token windows.Token
	if err := windows.DuplicateTokenEx(a.token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	sid, err := windows.StringToSid("S-1-16-4096")
	if err != nil {
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		t.Fatal(err)
	}
	low := *a
	low.token = token
	exe, _ := os.Executable()
	attack := low.command(exe, "client", "low-pipe")
	in, err := attack.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := attack.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	attack.Stderr = os.Stderr
	if err := attack.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); _ = attack.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "low integrity access checked:") {
		t.Fatal("low integrity attack precondition", line, err)
	}
	fresh := openClient(t, owner, false)
	defer fresh.input.Close()
	fresh.must(t, "session", nil, nil)
	t.Log(strings.TrimSpace(line))
	t.Log("medium owner connected before the probe released any permitted zero-access handles")
}
