package worker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type isolationRequest struct {
	Parent uint32
	Key    string
	TCP    [5]uint32
}
type isolationResult struct {
	Groups                                   map[string]uint32
	AdminDenyOnly                            bool
	Integrity                                string
	ProcessDenied, RegistryDenied, TCPDenied bool
	ProcessCode, RegistryCode, TCPCode       string
	Memory                                   uintptr
	UI                                       uint32
	ConsoleAttached                          bool
	Error                                    string
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		// Only this test executable handles these inputs. Product workers retain
		// their normal operation allowlist and never gain a diagnostic write API.
		if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
			os.Exit(2)
		}
		if len(os.Args) > 2 && os.Args[2] == "bootstrap-proof" {
			dll, err := windows.LoadLibraryEx("user32.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
			console, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleCP").Call()
			fmt.Printf("Go reached main; USER32=%v; console=%d; error=%v\n", dll, console, err)
			if err != nil {
				os.Exit(1)
			}
			windows.FreeLibrary(dll)
			os.Exit(0)
		}
		var input isolationRequest
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
			os.Exit(2)
		}
		result, err := isolationProbe(input)
		if err != nil {
			result.Error = err.Error()
		}
		_ = json.NewEncoder(os.Stdout).Encode(result)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestWorkerBootstrapDiagnostics(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	station, _, _ := user32.NewProc("GetProcessWindowStation").Call()
	desktop, _, _ := user32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	for name, handle := range map[string]uintptr{"station": station, "desktop": desktop} {
		sd, err := windows.GetSecurityInfo(windows.Handle(handle), windows.SE_WINDOW_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
		if err != nil {
			t.Logf("%s security: %v", name, err)
		} else {
			t.Logf("%s security: %s", name, sd.String())
		}
	}
	var empty uint16
	for _, test := range []struct {
		name      string
		desktop   *uint16
		flags, ui uint32
	}{
		{"inherited/no-window/all-UI-limits", nil, windows.CREATE_NO_WINDOW, 255},
		{"inherited/no-window/no-UI-limits", nil, windows.CREATE_NO_WINDOW, 0},
		{"inherited/detached/all-UI-limits", nil, windows.DETACHED_PROCESS, 255},
		{"automatic/no-window/all-UI-limits", &empty, windows.CREATE_NO_WINDOW, 255},
	} {
		t.Run(test.name, func(t *testing.T) {
			var p Process
			var err error
			if test.flags == windows.DETACHED_PROCESS {
				p, err = Start(exe, []string{"worker", "bootstrap-proof"})
			} else {
				p, err = start(exe, []string{"worker", "bootstrap-proof"}, test.desktop, test.flags, test.ui)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = p.Kill() })
			defer stop()
			p.Input().Close()
			b, _ := io.ReadAll(io.LimitReader(p.Output(), 65536))
			e, _ := io.ReadAll(io.LimitReader(p.Errors(), 65536))
			err = p.Wait()
			t.Logf("exit=%v; stdout=%s; stderr=%s", err, b, e)
			if test.flags == windows.DETACHED_PROCESS && (err != nil || !strings.Contains(string(b), "Go reached main") || !strings.Contains(string(b), "console=0")) {
				t.Fatal("production worker must initialize USER32 without a console")
			}
		})
	}
}

func isolationProbe(input isolationRequest) (isolationResult, error) {
	result := isolationResult{Groups: map[string]uint32{}}
	token := windows.GetCurrentProcessToken()
	groups, err := token.GetTokenGroups()
	if err != nil {
		return result, err
	}
	for _, g := range groups.AllGroups() {
		result.Groups[g.Sid.String()] = g.Attributes
		if g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			result.AdminDenyOnly = g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 && g.Attributes&windows.SE_GROUP_ENABLED == 0
		}
	}
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], size, &size); err != nil {
		return result, err
	}
	result.Integrity = (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0])).Label.Sid.String()
	h, err := windows.OpenProcess(windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_CREATE_THREAD, false, input.Parent)
	result.ProcessDenied = err == windows.ERROR_ACCESS_DENIED
	result.ProcessCode = fmt.Sprint(err)
	if err == nil {
		windows.CloseHandle(h)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, input.Key, registry.SET_VALUE)
	result.RegistryDenied = err == windows.ERROR_ACCESS_DENIED
	result.RegistryCode = fmt.Sprint(err)
	if err == nil {
		_ = k.SetStringValue("worker-write", "permitted")
		k.Close()
	}
	code, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetTcpEntry").Call(uintptr(unsafe.Pointer(&input.TCP[0])))
	// SetTcpEntry documents both 5 (access denied) and 317 (non-elevated).
	// The parent also proves the live connection survived this attempted close.
	result.TCPDenied = code == uintptr(windows.ERROR_ACCESS_DENIED) || code == 317
	result.TCPCode = strconv.FormatUint(uint64(code), 10)
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
		return result, err
	}
	result.Memory = limits.ProcessMemoryLimit
	var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := windows.QueryInformationJobObject(0, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)), nil); err != nil {
		return result, err
	}
	result.UI = ui.UIRestrictionsClass
	console, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleCP").Call()
	result.ConsoleAttached = console != 0
	return result, nil
}

func TestReadWorkerCannotWriteControlHKLMOrTCP(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("the parent must be elevated")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := uint32(os.Getpid())
	if value := os.Getenv("NETSWITCH_CONTROL_PID"); value != "" {
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil || pid == 0 {
			t.Fatalf("invalid Control PID %q", value)
		}
		parent = uint32(pid)
	}
	t.Logf("protected parent PID %d; live Control supplied: %t", parent, os.Getenv("NETSWITCH_CONTROL_PID") != "")
	key := `SOFTWARE\NetSwitchWorkerProof-` + strconv.Itoa(os.Getpid())
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, key) })
	for _, mode := range []string{"app-info", "installed-apps", "line-check", "probe", "meters", "network", "outside"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			local, remote := client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)
			port := func(p int) uint32 { return uint32((p&255)<<8 | p>>8) }
			input := isolationRequest{Parent: parent, Key: key, TCP: [5]uint32{12, binary.LittleEndian.Uint32(local.IP.To4()), port(local.Port), binary.LittleEndian.Uint32(remote.IP.To4()), port(remote.Port)}}
			args := []string{"worker", mode}
			if strings.Contains(mode, "-") {
				args = []string{"worker", "query", mode}
			}
			p, err := Start(exe, args)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if err := json.NewEncoder(p.Input()).Encode(input); err != nil {
				t.Fatal(err)
			}
			p.Input().Close()
			b, err := io.ReadAll(io.LimitReader(p.Output(), 65536))
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Wait(); err != nil {
				t.Fatal(err)
			}
			var got isolationResult
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(string(b), err)
			}
			t.Logf("%s: %+v", mode, got)
			if got.Error != "" || got.Memory != 256*1024*1024 || got.UI != 255 || got.ConsoleAttached {
				t.Fatalf("worker limits: %+v", got)
			}
			if mode == "outside" {
				if got.AdminDenyOnly || got.Integrity != "S-1-16-12288" || got.ProcessCode != "<nil>" || got.RegistryCode != "<nil>" || got.TCPCode != "0" {
					t.Fatalf("admin worker lost required writes: %+v", got)
				}
				if err := accepted.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				_, err := accepted.Read(make([]byte, 1))
				if err == nil {
					t.Fatal("admin close did not close the TCP connection")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("admin close left the TCP connection alive")
				}
			} else if !got.AdminDenyOnly || got.Integrity != "S-1-16-8192" || !got.ProcessDenied || !got.RegistryDenied || !got.TCPDenied {
				t.Fatalf("read worker retained authority: %+v", got)
			} else {
				for text, attributes := range got.Groups {
					sid, err := windows.StringToSid(text)
					if err != nil {
						t.Fatal(err)
					}
					if elevatedGroup(sid) && (attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 || attributes&(windows.SE_GROUP_ENABLED|windows.SE_GROUP_ENABLED_BY_DEFAULT) != 0) {
						t.Fatalf("elevated group retained by %s: %s attributes=%x", mode, text, attributes)
					}
				}
				for _, pair := range [][2]net.Conn{{client, accepted}, {accepted, client}} {
					for _, conn := range pair {
						if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := pair[0].Write([]byte{42}); err != nil {
						t.Fatalf("TCP connection was altered by read worker: %v", err)
					}
					var b [1]byte
					if _, err := io.ReadFull(pair[1], b[:]); err != nil || b[0] != 42 {
						t.Fatalf("TCP connection did not survive: %v %v", b, err)
					}
				}
				t.Log("TCP connection still carries data in both directions")
			}
		})
	}
}
