//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"unsafe"

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

// Microsoft documents skip-success as compatible only with providers that
// return IFS handles, detected by XP1_IFS_HANDLES in every WSAEnumProtocols
// entry. This catalog-wide check is kept as the documented gate, rather than
// Go's narrower TCP-only catalog. register adds the socket's own provider
// (SO_PROTOCOL_INFOW), which also sees a layered provider installed after
// this startup snapshot. Both must allow it. Do not filter the catalog.
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
