package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Bytes per network adapter: the same adapters, names and counters as .NET's
// NetworkInterface.GetAllNetworkInterfaces() and GetIPStatistics(), which the
// PowerShell version read. That is every adapter GetAdaptersAddresses lists,
// under its friendly name, with the byte counters GetIfEntry2 gives for its
// interface index. Not WMI: that can hang for minutes, and it doesn't list the
// USB Wi-Fi stick at all.
func readMeters() metersLine {
	line := metersLine{Adapters: []adapterReading{}}
	first, err := adapterAddresses(false)
	if err != nil {
		// .NET throws here, which left the PowerShell version with an empty list too.
		fmt.Fprintf(os.Stderr, "can't list the network adapters: %v\n", err)
		return line
	}
	var row windows.MibIfRow2
	for adapter := first; adapter != nil; adapter = adapter.Next {
		reading := adapterReading{Alias: windows.UTF16PtrToString(adapter.FriendlyName)}
		// .NET reports zeros, not an error, for an adapter without an interface index.
		if adapter.IfIndex != 0 {
			row = windows.MibIfRow2{InterfaceIndex: adapter.IfIndex}
			if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err != nil {
				// Left out of this second, like an adapter whose counters .NET can't read.
				continue
			}
			reading.RX, reading.TX = row.InOctets, row.OutOctets
		}
		line.Adapters = append(line.Adapters, reading)
	}
	return line
}

// Microsoft suggests starting with 15 KB. The buffer is kept and grows when
// the list doesn't fit.
var adapterBuffer = make([]byte, 15*1024)

// The first adapter of the list, or nil when there are none. Same flags as
// .NET, which only add details and don't change which adapters are listed.
func adapterAddresses(strict bool) (*windows.IpAdapterAddresses, error) {
	return queryAdapterAddresses(strict, windows.GetAdaptersAddresses)
}

func queryAdapterAddresses(strict bool, query func(uint32, uint32, uintptr, *windows.IpAdapterAddresses, *uint32) error) (*windows.IpAdapterAddresses, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_WINS_INFO
	for attempt := 0; attempt < 5; attempt++ {
		size := uint32(len(adapterBuffer))
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&adapterBuffer[0]))
		err := query(windows.AF_UNSPEC, flags, 0, first, &size)
		switch {
		case err == nil:
			return first, nil
		// .NET treats both as "no adapters".
		case errors.Is(err, windows.ERROR_NO_DATA), errors.Is(err, windows.ERROR_INVALID_PARAMETER):
			if strict {
				return nil, fmt.Errorf("read adapter addresses: %w", err)
			}
			return nil, nil
		case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
			adapterBuffer = make([]byte, size)
		default:
			return nil, err
		}
	}
	return nil, errors.New("the adapter list kept growing")
}
