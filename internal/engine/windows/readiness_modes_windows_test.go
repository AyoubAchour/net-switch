//go:build windows

package winengine

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func TestTCPCompletionProviderPolicy(t *testing.T) {
	ifs := windows.WSAProtocolInfo{ServiceFlags1: windows.XP1_IFS_HANDLES, Protocol: windows.IPPROTO_TCP}
	other := windows.WSAProtocolInfo{Protocol: windows.IPPROTO_UDP}
	many := make([]windows.WSAProtocolInfo, 40)
	for i := range many {
		many[i] = ifs
	}
	for _, tc := range []struct {
		name    string
		entries []windows.WSAProtocolInfo
		probe   error
		query   error
		badSize bool
		badN    bool
		allow   bool
		reason  string
	}{
		{name: "all-IFS", entries: []windows.WSAProtocolInfo{ifs, ifs}, allow: true, reason: "all-ifs"},
		{name: "large-all-IFS", entries: many, allow: true, reason: "all-ifs"},
		{name: "non-IFS-beyond-32", entries: append(append([]windows.WSAProtocolInfo{}, many...), other), reason: "non-ifs-provider"},
		{name: "non-TCP-non-IFS", entries: []windows.WSAProtocolInfo{ifs, other}, reason: "non-ifs-provider"},
		{name: "non-IFS-first", entries: []windows.WSAProtocolInfo{other, ifs}, reason: "non-ifs-provider"},
		{name: "empty", reason: "provider-query-error"},
		{name: "sizing-error", probe: windows.WSAENETDOWN, reason: "provider-query-error"},
		{name: "catalog-error", entries: []windows.WSAProtocolInfo{ifs}, query: windows.WSAEFAULT, reason: "provider-query-error"},
		{name: "catalog-grew", entries: []windows.WSAProtocolInfo{ifs}, query: windows.WSAENOBUFS, reason: "provider-query-error"},
		{name: "unbounded-size", badSize: true, reason: "provider-query-error"},
		{name: "invalid-count", entries: []windows.WSAProtocolInfo{ifs}, badN: true, reason: "provider-query-error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			policy := queryTCPCompletionPolicy(func(filter *int32, buffer *windows.WSAProtocolInfo, size *uint32) (int32, error) {
				calls++
				if filter != nil {
					t.Fatal("provider enumeration excluded protocols")
				}
				if calls > 2 {
					t.Fatal("unexpected retry hid a catalog error")
				}
				if buffer == nil {
					if tc.probe != nil {
						return -1, tc.probe
					}
					*size = uint32(len(tc.entries)) * uint32(unsafe.Sizeof(windows.WSAProtocolInfo{}))
					if tc.badSize {
						*size = ^uint32(0)
					}
					if *size == 0 {
						return 0, nil
					}
					return -1, windows.WSAENOBUFS
				}
				if tc.query != nil {
					return -1, tc.query
				}
				copy(unsafe.Slice(buffer, len(tc.entries)), tc.entries)
				if tc.badN {
					return int32(len(tc.entries) + 1), nil
				}
				return int32(len(tc.entries)), nil
			})
			if policy.allowSkip != tc.allow || policy.reason != tc.reason {
				t.Fatalf("policy = %+v", policy)
			}
			if policy.err == nil && policy.entries != len(tc.entries) || (policy.nonIFS != "") != (tc.reason == "non-ifs-provider") {
				t.Fatalf("lost provider catalog evidence: %+v", policy)
			}
			if (policy.err != nil) != (tc.reason == "provider-query-error") {
				t.Fatalf("missing or spurious query diagnostic: %v", policy.err)
			}
			if tc.probe != nil && !errors.Is(policy.err, tc.probe) || tc.query != nil && !errors.Is(policy.err, tc.query) {
				t.Fatalf("query diagnostic lost its cause: %v", policy.err)
			}
		})
	}
}

func TestTCPCompletionModeQueryRejectsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   uint32
		bytes  uintptr
		status windows.NTStatus
		err    error
		valid  bool
	}{
		{name: "normal", bytes: 4, valid: true},
		{name: "inherited-skip", mode: windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, bytes: 4, valid: true},
		{name: "unsupported", err: windows.STATUS_INVALID_INFO_CLASS},
		{name: "short-result", bytes: 3},
		{name: "oversize-result", bytes: 8},
		{name: "status-failure", bytes: 4, status: windows.STATUS_INVALID_HANDLE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modes, err := querySocketCompletionModes(123, func(h windows.Handle, status *windows.IO_STATUS_BLOCK, out *byte, size, class uint32) error {
				if h != 123 || size != 4 || class != 41 {
					t.Fatalf("wrong native query contract: handle=%d size=%d class=%d", h, size, class)
				}
				*(*uint32)(unsafe.Pointer(out)) = tc.mode
				status.Information, status.Status = tc.bytes, tc.status
				return tc.err
			})
			if tc.valid {
				if err != nil || modes != tc.mode {
					t.Fatalf("valid query: modes=%#x err=%v", modes, err)
				}
				return
			}
			if err == nil || modes != 0 {
				t.Fatalf("unknown mode accepted: modes=%#x err=%v", modes, err)
			}
			// No native calls are permitted after an unknown mode. Even an
			// uninitialized pool/owner is safe: watch must return at the query.
			p := &readiness{queryModes: func(winhandle.Owner) (uint32, error) { return 0, err }}
			w, watchErr := p.watch(winhandle.Owner{}, 0, func() { t.Error("unknown-mode callback") })
			if w != nil || !errors.Is(watchErr, err) || p.next != 0 || p.immediate.Load() != 0 || p.submitted.Load() != 0 {
				t.Fatalf("unknown mode entered registration or receive: watch=%v error=%v", w, watchErr)
			}
		})
	}
}
