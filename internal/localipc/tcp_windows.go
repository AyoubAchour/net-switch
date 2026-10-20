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
	buffer := make([]byte, 65536)
	for range 5 {
		size := uint32(len(buffer))
		code, _, _ := getTCPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 4, 0) // TCP_TABLE_OWNER_PID_CONNECTIONS
		if windows.Errno(code) == windows.ERROR_INSUFFICIENT_BUFFER {
			if size > 32<<20 {
				return "", errors.New("TCP owner table exceeds limit")
			}
			buffer = make([]byte, size+4096)
			continue
		}
		if code != 0 {
			return "", windows.Errno(code)
		}
		if len(buffer) < 4 {
			return "", ErrPeer
		}
		count := int(binary.LittleEndian.Uint32(buffer))
		if count > (len(buffer)-4)/24 {
			return "", ErrPeer
		}
		for i := range count {
			row := buffer[4+i*24 : 4+(i+1)*24]
			if binary.LittleEndian.Uint32(row) != 5 ||
				!net.IP(row[4:8]).Equal(client.IP) || int(binary.BigEndian.Uint16(row[8:10])) != client.Port ||
				!net.IP(row[12:16]).Equal(server.IP) || int(binary.BigEndian.Uint16(row[16:18])) != server.Port {
				continue
			}
			peer, err := processPeer(binary.LittleEndian.Uint32(row[20:24]))
			return peer.User, err
		}
		return "", ErrPeer
	}
	return "", errors.New("TCP owner table kept changing")
}
