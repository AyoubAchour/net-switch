package lifecycle_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"golang.org/x/sys/windows"
)

func tokenIntegrity() (string, error) {
	var info [64]uint64
	var size uint32
	if err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&info[0])), uint32(unsafe.Sizeof(info)), &size); err != nil {
		return "", err
	}
	return (*windows.Tokenmandatorylabel)(unsafe.Pointer(&info[0])).Label.Sid.String(), nil
}

// grantedAccess reads a handle's granted access mask (OBJECT_BASIC_INFORMATION).
func grantedAccess(h windows.Handle) (uint32, error) {
	var info [56 / 4]uint32
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject").Call(uintptr(h), 0, uintptr(unsafe.Pointer(&info[0])), unsafe.Sizeof(info), 0)
	if status != 0 {
		return 0, fmt.Errorf("NtQueryObject: NTSTATUS 0x%x", status)
	}
	return info[1], nil
}

// mediumPipeRead is the control for the low-integrity probe: the same owner
// SID at medium integrity may open the desktop pipe for reading, so a low
// integrity denial of the identical open comes from the mandatory label.
func mediumPipeRead() error {
	level, err := tokenIntegrity()
	if err != nil {
		return err
	}
	if level != "S-1-16-8192" {
		return fmt.Errorf("control probe is not medium integrity: %s", level)
	}
	path, _ := windows.UTF16PtrFromString(localipc.DefaultPath("desktop"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		h, err := windows.CreateFile(path, windows.FILE_READ_DATA, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			windows.CloseHandle(h)
			fmt.Println("medium read open allowed")
			return nil
		}
		if err != windows.ERROR_PIPE_BUSY || time.Now().After(deadline) {
			return fmt.Errorf("medium owner read open: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func lowPipeClient() error {
	level, err := tokenIntegrity()
	if err != nil {
		return err
	}
	if level != "S-1-16-4096" {
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
		} else if err != windows.ERROR_PIPE_BUSY {
			return err
		}
	}
	if readDenied == 0 || zeroDenied+len(held) == 0 {
		return errors.New("pipe busy responses did not prove integrity enforcement")
	}
	// Win32 CreateFile(0) adds SYNCHRONIZE and FILE_READ_ATTRIBUTES, which
	// the no-read-up label denies. A truly empty access mask has no read
	// or write bit for the label to deny, so try that too: whatever opens
	// must carry no access and be unable to read.
	desktopNT := ntPipePath("desktop")
	check := func(h windows.Handle) error {
		access, err := grantedAccess(h)
		if err != nil {
			return err
		}
		if access != 0 {
			return fmt.Errorf("zero-access open was granted 0x%x", access)
		}
		var n uint32
		if err := windows.ReadFile(h, make([]byte, 1), &n, nil); err == nil {
			return errors.New("zero-access pipe handle could read")
		}
		return nil
	}
	ntOpened, ntDenied := 0, 0
	for range 64 {
		h, err := ntZeroOpen(desktopNT)
		switch {
		case err == nil:
			ntOpened++
			checkErr := check(h)
			windows.CloseHandle(h)
			if checkErr != nil {
				return checkErr
			}
		case errors.Is(err, windows.STATUS_ACCESS_DENIED) || errors.Is(err, windows.ERROR_ACCESS_DENIED):
			ntDenied++
		case errors.Is(err, windows.STATUS_PIPE_NOT_AVAILABLE) || errors.Is(err, windows.ERROR_PIPE_BUSY):
		default:
			return fmt.Errorf("zero-access NtCreateFile: %w", err)
		}
	}
	if ntOpened+ntDenied == 0 {
		return errors.New("no zero-access NtCreateFile attempt reached the pipe")
	}
	// Keep zero-access opens going while the parent connects the medium
	// owner, so owner admission is proven under this load, not after it.
	stop := make(chan struct{})
	var workers sync.WaitGroup
	var flooded atomic.Uint64
	for range 4 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if h, err := ntZeroOpen(desktopNT); err == nil {
					flooded.Add(1)
					time.Sleep(300 * time.Millisecond)
					windows.CloseHandle(h)
				} else {
					time.Sleep(2 * time.Millisecond)
				}
			}
		})
	}
	fmt.Printf("low integrity access checked: read_denied=%d zero_denied=%d zero_held=%d nt_zero_opened=%d nt_zero_denied=%d\n", readDenied, zeroDenied, len(held), ntOpened, ntDenied)
	_, err = io.Copy(io.Discard, os.Stdin)
	close(stop)
	workers.Wait()
	fmt.Printf("sustained zero-access opens during owner admission: %d\n", flooded.Load())
	return err
}

// lowActor is the owner's logon with its token lowered to low integrity.
func lowActor(t *testing.T, owner actor) *windowsActor {
	t.Helper()
	a := owner.(*windowsActor)
	var token windows.Token
	if err := windows.DuplicateTokenEx(a.token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { token.Close() })
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
	return &low
}

func lowIntegrityCapacity(t *testing.T, owner actor) {
	exe, _ := os.Executable()
	if b, err := owner.command(exe, "client", "medium-pipe-read").CombinedOutput(); err != nil || !strings.Contains(string(b), "medium read open allowed") {
		t.Fatal("medium owner control open", err, string(b))
	}
	low := lowActor(t, owner)
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
	reader := bufio.NewReader(out)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "low integrity access checked:") {
		in.Close()
		_ = attack.Wait()
		t.Fatal("low integrity attack precondition", line, err)
	}
	started := time.Now()
	fresh := openClient(t, owner, false)
	fresh.must(t, "session", nil, nil)
	admitted := time.Since(started)
	fresh.input.Close()
	in.Close()
	final, _ := reader.ReadString('\n')
	if err := attack.Wait(); err != nil {
		t.Fatal(err)
	}
	if admitted > 20*time.Second {
		t.Fatal("medium owner admission under low-integrity load took", admitted)
	}
	t.Log(strings.TrimSpace(line))
	t.Log(strings.TrimSpace(final))
	t.Log("the same owner SID opened the pipe for reading at medium integrity and was denied at low integrity, so the mandatory label, not the DACL, denies it")
	t.Logf("medium owner connected in %s while zero-access opens continued", admitted.Round(time.Millisecond))
}

// lowIntegrityPairing proves the TCP identity floor: the owner's own SID at
// low integrity is refused pairing before any code attempt is used, and the
// same code then still pairs the medium owner.
func lowIntegrityPairing(t *testing.T, c *client, owner actor) {
	var session struct{ Token, URL string }
	c.must(t, "session", nil, &session)
	var code string
	c.must(t, "pair", nil, &code)
	low := lowActor(t, owner)
	for range 3 {
		if status, body := apiAs(t, low, session.URL, "", "POST", "/api/pair", `{"code":"`+code+`"}`); status != 403 {
			t.Fatal("low-integrity owner process reached pairing", status, string(body))
		}
	}
	if status, body := apiAs(t, owner, session.URL, "", "POST", "/api/pair", `{"code":"`+code+`"}`); status != 200 {
		t.Fatal("medium owner could not pair after low-integrity refusals", status, string(body))
	}
	t.Log("low-integrity owner process refused pairing three times without using an attempt; the medium owner paired with the same code")
}
