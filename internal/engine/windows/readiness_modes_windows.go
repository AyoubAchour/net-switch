//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

type tcpCompletionPolicy struct {
	allowSkip bool
	reason    string
	err       error
	entries   int
	nonIFS    string
}

type protocolEnumerator func(*int32, *windows.WSAProtocolInfo, *uint32) (int32, error)

// Microsoft documents non-IFS LSPs as incompatible with skip-success. Our
// enabling policy checks every returned provider for XP1_IFS_HANDLES, rather
// than Go's narrower TCP catalog and selected-socket checks. Do not filter it.
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes
func queryTCPCompletionPolicy(enumerate protocolEnumerator) tcpCompletionPolicy {
	failure := func(err error) tcpCompletionPolicy {
		return tcpCompletionPolicy{reason: "provider-query-error", err: err}
	}
	var size uint32
	_, err := enumerate(nil, nil, &size)
	if !errors.Is(err, windows.WSAENOBUFS) {
		if err == nil {
			err = errors.New("empty provider catalog")
		}
		return failure(fmt.Errorf("WSAEnumProtocols sizing: %w", err))
	}
	entrySize := uint32(unsafe.Sizeof(windows.WSAProtocolInfo{}))
	// A changing or unexpectedly large catalog disables the optimization. It
	// must not turn initialization into an unbounded allocation or retry loop.
	if size < entrySize || size > 1<<20 {
		return failure(fmt.Errorf("WSAEnumProtocols buffer size %d", size))
	}
	entries := make([]windows.WSAProtocolInfo, (size+entrySize-1)/entrySize)
	size = uint32(len(entries)) * entrySize
	n, err := enumerate(nil, &entries[0], &size)
	if err != nil {
		return failure(fmt.Errorf("WSAEnumProtocols catalog: %w", err))
	}
	if n <= 0 || int(n) > len(entries) {
		return failure(fmt.Errorf("WSAEnumProtocols returned %d entries for %d slots", n, len(entries)))
	}
	for _, entry := range entries[:n] {
		if entry.ServiceFlags1&windows.XP1_IFS_HANDLES == 0 {
			return tcpCompletionPolicy{reason: "non-ifs-provider", entries: int(n),
				nonIFS: fmt.Sprintf("%s (catalog %d, family %d, protocol %d, chain %d)",
					windows.UTF16ToString(entry.ProtocolName[:]), entry.CatalogEntryId,
					entry.AddressFamily, entry.Protocol, entry.ProtocolChain.ChainLen)}
		}
	}
	return tcpCompletionPolicy{allowSkip: true, reason: "all-ifs", entries: int(n)}
}

// A Go TCP socket may already have skip-success enabled, even if our broader
// provider query forbids enabling it (or fails). The mode is shared by socket
// duplicates and cannot be cleared. Reading it is essential: guessing normal
// notifications would wait forever for a suppressed synchronous completion.
// FileIoCompletionNotificationInformation (41) exists since Vista, but Microsoft
// labels it reserved for system use. The pinned Go toolchain also queries it
// when retaining borrowed completion modes. Treat this as a compatibility
// dependency, not a promise that every provider implements the query: require
// success and the complete Flags word, or fail before submitting any receive.
// QueryInformationFile itself is synchronous even for an asynchronous file
// object (IRP_SYNCHRONOUS_API); user-mode Nt and Zw entry points have identical
// behavior. Its caller buffers therefore are not retained after this call.
// https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioisoperationsynchronous
// https://learn.microsoft.com/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines
func socketCompletionModes(socket winhandle.Owner) (uint32, error) {
	return querySocketCompletionModes(socket.Handle("TCP query completion modes"), windows.NtQueryInformationFile)
}

type completionModeQuery func(windows.Handle, *windows.IO_STATUS_BLOCK, *byte, uint32, uint32) error

func querySocketCompletionModes(handle windows.Handle, query completionModeQuery) (uint32, error) {
	var modes uint32
	var status windows.IO_STATUS_BLOCK
	err := query(handle, &status,
		(*byte)(unsafe.Pointer(&modes)), uint32(unsafe.Sizeof(modes)), 41)
	if err != nil {
		return 0, fmt.Errorf("TCP completion modes query: %w", err)
	}
	if status.Status != 0 {
		return 0, fmt.Errorf("TCP completion modes status: %w", status.Status)
	}
	if status.Information != unsafe.Sizeof(modes) {
		return 0, fmt.Errorf("TCP completion modes query returned %d bytes", status.Information)
	}
	return modes, nil
}
