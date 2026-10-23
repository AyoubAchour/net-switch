//go:build windows

package wintun

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/platform/winapi"
	"github.com/AyoubAchour/net-switch/internal/platform/winchild"
	"golang.org/x/sys/windows"
)

// Hosted helpers use the real launch/registrar paths. The outer test retains
// the adapter's creator handle, so recovery cannot pass because it disappeared.
func TestWintunSupervisorChild(t *testing.T) {
	value := os.Getenv("NETSWITCH_WINTUN_SUPERVISED_CHILD")
	if value == "" {
		t.Skip("supervised child only")
	}
	requireRunner(t)
	stage, guid, ok := strings.Cut(value, ",")
	if !ok {
		t.Fatal("invalid child fixture")
	}
	must(t, ConfigureSupervisorChild(func(ctx context.Context, registrar winchild.Registrar) error {
		message, err := json.Marshal(registrar)
		if err != nil {
			return err
		}
		fmt.Printf("REGISTRAR_OBSERVE %s\n", message)
		ack := make(chan error, 1)
		go func() {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err == nil && line != "REGISTRAR_ACK\n" {
				err = fmt.Errorf("unexpected observer acknowledgement %q", line)
			}
			ack <- err
		}()
		select {
		case err := <-ack:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}))
	provenance := productionEngine(t)
	registrarExecutable = func() (string, error) { return provenance.Path, nil }
	registrarBeforeResume = func(pid uint32, job windows.Handle) {
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		must(t, err)
		var member uint32
		ok, _, membershipErr := isProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
		must(t, windows.CloseHandle(process))
		if ok == 0 || member == 0 {
			t.Fatalf("registrar not in its own restricted job: member=%d error=%v", member, membershipErr)
		}
		var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
		must(t, winapi.QueryJobInformation(job, windows.JobObjectExtendedLimitInformation, &limits))
		must(t, winapi.QueryJobInformation(job, windows.JobObjectBasicUIRestrictions, &ui))
		flags := limits.BasicLimitInformation.LimitFlags
		if ui.UIRestrictionsClass != 255 || limits.BasicLimitInformation.ActiveProcessLimit != 1 || flags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 || flags&(windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK|windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0 {
			t.Fatalf("registrar containment weakened: ui=%#x flags=%#x count=%d", ui.UIRestrictionsClass, flags, limits.BasicLimitInformation.ActiveProcessLimit)
		}
		fmt.Printf("REGISTRAR_CREATED %d ui=%#x flags=%#x active=1\n", pid, ui.UIRestrictionsClass, flags)
		if strings.Contains(stage, "registrar-suspended") {
			blockForever()
		}
	}
	a, err := Open(Config{Name: "NsRingCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	f := fixtureOnAdapter(t, "ours", a)
	exchange(t, 16)
	if f.faults.Load() != 0 {
		t.Fatal(f.fault())
	}
	fmt.Printf("SUPERVISED_READY %d\n", f.io.(*Session).Stats().Registrar.PID)
	blockForever()
}

func TestWintunSupervisorHost(t *testing.T) {
	value := os.Getenv("NETSWITCH_WINTUN_SUPERVISOR")
	if value == "" {
		t.Skip("supervisor fixture only")
	}
	requireRunner(t)
	stage, _, ok := strings.Cut(value, ",")
	if !ok {
		t.Fatal("invalid host fixture")
	}
	p, err := winchild.StartSelf(winchild.Options{
		Args: []string{"-test.run=^TestWintunSupervisorChild$", "-test.v"},
		Env:  append(os.Environ(), "NETSWITCH_WINTUN_SUPERVISED_CHILD="+value), RegistrarBreakaway: true,
	})
	must(t, err)
	defer p.Close()
	id, err := json.Marshal(p.Identity)
	must(t, err)
	fmt.Printf("SUPERVISOR_CHILD %s\n", id)
	if stage == "host-child-suspended" {
		blockForever()
	}
	must(t, p.Resume())
	errorsDone := make(chan struct{})
	go func() { defer close(errorsDone); io.Copy(io.Discard, p.Errors) }()
	scan := bufio.NewScanner(p.Output)
	var tail []string
	for scan.Scan() {
		line := scan.Text()
		if rest, ok := strings.CutPrefix(line, "REGISTRAR_OBSERVE "); ok {
			var registrar winchild.Registrar
			must(t, json.Unmarshal([]byte(rest), &registrar))
			must(t, p.TrackRegistrar(registrar)) // production handle handoff, before resume
			_, err := io.WriteString(p.Input, "REGISTRAR_ACK\n")
			must(t, err)
		} else if rest, ok := strings.CutPrefix(line, "REGISTRAR_CREATED "); ok {
			fields := strings.Fields(rest)
			pid, err := strconv.ParseUint(fields[0], 10, 32)
			must(t, err)
			h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
			must(t, err)
			inside, checkErr := p.Contains(h)
			closeErr := windows.CloseHandle(h)
			must(t, checkErr)
			must(t, closeErr)
			if inside {
				t.Fatal("UI-restricted registrar still nested in the native child job")
			}
			fmt.Printf("REGISTRAR_SEPARATE %s\n", rest)
		} else if strings.HasPrefix(line, "SUPERVISED_READY ") {
			fmt.Println(line)
		} else {
			if len(line) > 2048 {
				line = line[:2048]
			}
			tail = append(tail, line)
			if len(tail) > 20 {
				tail = tail[1:]
			}
		}
	}
	if scan.Err() != nil {
		p.Terminate()
		t.Fatal(scan.Err())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exit, err := p.Wait(ctx)
	must(t, err)
	must(t, p.Close())
	<-errorsDone
	fmt.Printf("SUPERVISOR_RAW_EXIT code=%#x forced=%t tail=%q\n", exit.Code, exit.Forced, tail)
	if exit.Code != 0 {
		os.Exit(1)
	}
}

func TestWintunSupervisorContainment(t *testing.T) {
	requireRunner(t)
	productionEngine(t) // require the real uninstrumented registrar and its hash
	for _, stage := range []string{"host-child-suspended", "host-registrar-suspended", "child-registrar-suspended", "host-ready", "child-ready"} {
		t.Run(stage, func(t *testing.T) {
			a := newAdapter(t, MinCapacity)
			host := startChild(t, "TestWintunSupervisorHost", "NETSWITCH_WINTUN_SUPERVISOR="+stage+","+a.config.GUID,
				[]string{"SUPERVISOR_CHILD ", "REGISTRAR_SEPARATE ", "SUPERVISED_READY ", "SUPERVISOR_RAW_EXIT "}, nil)
			var id winchild.Identity
			must(t, json.Unmarshal([]byte(host.await(t, "SUPERVISOR_CHILD ", 20*time.Second)), &id))
			child, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, id.PID)
			must(t, err)
			defer windows.CloseHandle(child)
			var created, ended, kernel, user windows.Filetime
			must(t, windows.GetProcessTimes(child, &created, &ended, &kernel, &user))
			if id.Created != uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) {
				t.Fatal("child identity changed before independent pin")
			}
			if dead, _ := exitState(child, 0); dead {
				t.Fatal("child not live before fault")
			}
			var registrar windows.Handle
			if stage != "host-child-suspended" {
				line := host.await(t, "REGISTRAR_SEPARATE ", 25*time.Second)
				fields := strings.Fields(line)
				pid, err := strconv.ParseUint(fields[0], 10, 32)
				must(t, err)
				registrar, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
				must(t, err)
				defer windows.CloseHandle(registrar)
				if dead, _ := exitState(registrar, 0); dead {
					t.Fatal("registrar not live before fault")
				}
				if !strings.Contains(line, "ui=0xff") || !strings.Contains(line, "active=1") {
					t.Fatal("missing native job evidence", line)
				}
				if strings.HasSuffix(stage, "ready") {
					ready := host.await(t, "SUPERVISED_READY ", 25*time.Second)
					if ready != fields[0] {
						t.Fatal("registered helper identity changed", ready, line)
					}
				}
			}
			start := time.Now()
			if strings.HasPrefix(stage, "host-") {
				must(t, host.cmd.Process.Kill())
			} else {
				must(t, windows.TerminateProcess(child, 37))
			}
			dead, childCode := exitState(child, 5*time.Second)
			if !dead {
				t.Fatal("child survived host/child termination", childCode)
			}
			if strings.HasPrefix(stage, "child-") && childCode != 37 {
				t.Fatal("explicit termination code changed", childCode)
			}
			hostCode := host.join(t, 10*time.Second)
			if hostCode == 0 || hostCode == 3 {
				t.Fatal("host observer classified forced loss as clean stop/adapter loss", hostCode, childCode)
			}
			// Same creator and adapter; a new registration and traffic prove the
			// earlier registration was released, not hidden by adapter removal.
			fresh := fixtureOnAdapter(t, "ours", a)
			exchange(t, 16)
			fresh.stopEcho()
			must(t, fresh.io.Close())
			// Check only AFTER recovery: production's registrar observer (or the
			// bounded registration path after host death) must close the race.
			if registrar != 0 {
				if dead, _ := exitState(registrar, 0); !dead {
					t.Fatal("registrar survived recovery")
				}
			}
			report(t, map[string]any{"test": "supervisor_containment", "stage": stage, "child": id,
				"raw_child_exit": childCode, "host_exit": hostCode, "outcome_source": "host", "classified_failure": true,
				"elapsed_ms": time.Since(start).Milliseconds(), "same_adapter_recovered": true, "ui_restrictions_preserved": true})
		})
	}
}
