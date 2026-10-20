package localipc

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// TCPOwner resolves the client side of an established IPv4 loopback tuple.
// Looking up only the port would accept an unrelated socket or the server.
func TCPOwner(client, server *net.TCPAddr) (string, error) {
	if !client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return "", ErrPeer
	}
	words := make([]uint64, 8192)
	for range 5 {
		buffer := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
		size := uint32(len(buffer))
		code, _, _ := getTCPTable.Call(uintptr(unsafe.Pointer(&words[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 7, 0) // TCP_TABLE_OWNER_MODULE_CONNECTIONS
		if windows.Errno(code) == windows.ERROR_INSUFFICIENT_BUFFER {
			if size > 32<<20 {
				return "", errors.New("TCP owner table exceeds limit")
			}
			words = make([]uint64, (size+4096+7)/8)
			continue
		}
		if code != 0 {
			return "", windows.Errno(code)
		}
		if len(buffer) < 4 {
			return "", ErrPeer
		}
		count := int(binary.LittleEndian.Uint32(buffer))
		// MIB_TCPROW_OWNER_MODULE is 160 bytes aligned to eight. Its table
		// header has four bytes of padding before the first row on x64/ARM64.
		if count > (int(size)-8)/160 {
			return "", ErrPeer
		}
		for i := range count {
			row := buffer[8+i*160 : 8+(i+1)*160]
			if binary.LittleEndian.Uint32(row) != 5 ||
				!net.IP(row[4:8]).Equal(client.IP) || int(binary.BigEndian.Uint16(row[8:10])) != client.Port ||
				!net.IP(row[12:16]).Equal(server.IP) || int(binary.BigEndian.Uint16(row[16:18])) != server.Port {
				continue
			}
			created := binary.LittleEndian.Uint64(row[24:32])
			if created == 0 {
				return "", ErrPeer
			}
			peer, err := processPeerAt(binary.LittleEndian.Uint32(row[20:24]), created)
			return peer.User, err
		}
		return "", ErrPeer
	}
	return "", errors.New("TCP owner table kept changing")
}
