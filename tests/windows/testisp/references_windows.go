//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func referenceRecord(kind string, value any) {
	b, _ := json.Marshal(value)
	fmt.Printf("ADAPTER_REFERENCES %s %s\n", kind, b)
}

// Separate hosted helper, killed by the harness after eight seconds. Querying
// a remote file name requires a temporary duplicate; never do this on the
// engine's teardown thread. The duplicate can itself delay PnP removal until
// closed, so the log explicitly brackets this potentially perturbing interval.
func observeReferences() error {
	referenceRecord("begin", map[string]any{"pid": os.Getpid(), "utc": time.Now().UTC(), "temporaryDuplicates": true})
	defer referenceRecord("end", map[string]any{"pid": os.Getpid()})
	for _, tcp := range []bool{true, false} {
		for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
			if err := referenceEndpoints(tcp, family); err != nil {
				referenceRecord("endpoint-error", err.Error())
			}
		}
	}
	processes := map[uint32]string{}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if strings.Contains(name, "netswitch") || strings.Contains(name, "testisp") || name == "node.exe" || name == "acceptance-app.exe" || name == "lifecycle.test.exe" {
			processes[entry.ProcessID] = name
			referenceRecord("process", map[string]any{"pid": entry.ProcessID, "parent": entry.ParentProcessID, "name": name})
		}
	}
	windows.CloseHandle(snapshot)
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return err
	}
	var words []uint64
	for size := uint32(1 << 20); ; size *= 2 {
		if size > 64<<20 {
			return errors.New("handle inventory exceeds 64 MiB")
		}
		words = make([]uint64, size/8)
		var used uint32
		err = windows.NtQuerySystemInformation(windows.SystemExtendedHandleInformation, unsafe.Pointer(&words[0]), size, &used)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			return err
		}
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	n := binary.LittleEndian.Uint64(b)
	if n > uint64((len(b)-16)/40) {
		return errors.New("invalid handle inventory length")
	}
	queried := 0
	for i := uint64(0); i < n; i++ {
		row := b[16+i*40 : 16+(i+1)*40]
		pid := uint32(binary.LittleEndian.Uint64(row[8:]))
		if processes[pid] == "" || pid == uint32(os.Getpid()) {
			continue
		}
		queried++
		if queried > 8192 {
			return errors.New("handle inventory exceeds 8192 selected handles; incomplete")
		}
		handle := windows.Handle(binary.LittleEndian.Uint64(row[16:]))
		record := map[string]any{"pid": pid, "handle": uint64(handle), "object": fmt.Sprintf("%x", binary.LittleEndian.Uint64(row)), "typeIndex": binary.LittleEndian.Uint16(row[30:])}
		// Emit the identity before a potentially blocking name query, so a
		// timed-out helper still identifies exactly where the inventory stopped.
		referenceRecord("handle", record)
		process, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
		if err != nil {
			continue
		}
		var duplicate windows.Handle
		err = windows.DuplicateHandle(process, handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS)
		windows.CloseHandle(process)
		if err != nil {
			continue // Closed/reused since the snapshot; never interpret as absence.
		}
		kind, _ := windows.GetFileType(duplicate)
		objectType, _ := referenceObjectString(duplicate, 2)
		// Pipe name queries can wait on pending I/O. Sockets and pipes are
		// covered by endpoint and in-process registration inventories instead.
		if kind != windows.FILE_TYPE_PIPE && objectType == "File" {
			name, nameErr := referenceObjectString(duplicate, 1)
			record["name"], record["nameError"] = name, fmt.Sprint(nameErr)
			referenceRecord("file", record)
		}
		windows.CloseHandle(duplicate)
	}
	return nil
}

func referenceObjectString(handle windows.Handle, class uintptr) (string, error) {
	words := make([]uint64, 8192) // aligned, at most 64 KiB per name
	var used uint32
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject").Call(uintptr(handle), class,
		uintptr(unsafe.Pointer(&words[0])), uintptr(len(words)*8), uintptr(unsafe.Pointer(&used)))
	if status != 0 {
		return "", fmt.Errorf("NtQueryObject status %#x", status)
	}
	// UNICODE_STRING on the supported 64-bit Windows architectures.
	length := uint16(words[0])
	start, base := uintptr(words[1]), uintptr(unsafe.Pointer(&words[0]))
	if length == 0 {
		return "", nil
	}
	if length%2 != 0 || start < base || start-base > uintptr(len(words)*8)-uintptr(length) {
		return "", errors.New("invalid object name")
	}
	data := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(&words[0]), start-base)), int(length)/2)
	return windows.UTF16ToString(data), nil
}

func referenceEndpoints(tcp bool, family uint32) error {
	name, class, stride := "GetExtendedUdpTable", uintptr(1), 12
	if tcp {
		name, class, stride = "GetExtendedTcpTable", 5, 24
	}
	if family == windows.AF_INET6 {
		stride = 28
		if tcp {
			stride = 56
		}
	}
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc(name)
	size := uint32(1 << 20)
	for attempt := 0; attempt < 3 && size <= 16<<20; attempt++ {
		words := make([]uint64, (size+7)/8)
		result, _, _ := proc.Call(uintptr(unsafe.Pointer(&words[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), class, 0)
		if result == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if result != 0 {
			return fmt.Errorf("%s family %d: %d", name, family, result)
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
		count := int(binary.LittleEndian.Uint32(b))
		if count > (len(b)-4)/stride {
			return errors.New("invalid endpoint table length")
		}
		matched := 0
		for i := 0; i < count; i++ {
			row := b[4+i*stride : 4+(i+1)*stride]
			var address netip.Addr
			portOffset, pidOffset := 4, 8
			if family == windows.AF_INET6 {
				address = netip.AddrFrom16([16]byte(row[:16]))
				portOffset, pidOffset = 20, 24
				if tcp {
					pidOffset = 52
				}
			} else if tcp {
				address = netip.AddrFrom4([4]byte(row[4:8]))
				portOffset, pidOffset = 8, 20
			} else {
				address = netip.AddrFrom4([4]byte(row[:4]))
			}
			if address.String() != "198.18.0.1" && address.String() != "fdfe:dcba:9876::1" {
				continue
			}
			matched++
			if matched <= 256 {
				record := map[string]any{"table": name, "family": family, "address": address.String(), "port": binary.BigEndian.Uint16(row[portOffset:]), "pid": binary.LittleEndian.Uint32(row[pidOffset:])}
				if tcp {
					stateOffset := 0
					if family == windows.AF_INET6 {
						stateOffset = 48
					}
					record["state"] = binary.LittleEndian.Uint32(row[stateOffset:])
				}
				referenceRecord("endpoint", record)
			}
		}
		referenceRecord("endpoint-count", map[string]any{"table": name, "family": family, "matched": matched, "detailsTruncated": matched > 256})
		return nil
	}
	return errors.New("endpoint inventory exceeds bounded buffer or retries")
}
