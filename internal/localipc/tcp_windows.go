package localipc

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

type tcpKey struct {
	client, server [4]byte
	clientPort     uint16
	serverPort     uint16
}

type tcpOwner struct {
	pid     uint32
	created uint64 // FILETIME of the connection
}

// TCPOwners resolves a batch of established IPv4 loopback tuples from one
// machine-wide TCP table snapshot. Matching the full tuple, not just a port,
// rules out an unrelated socket or the server's own end. The snapshot's cost
// grows with every connection on the machine, which other users control, so
// callers resolve whole batches instead of taking a snapshot per connection.
func TCPOwners(tuples []TCPTuple) []TCPIdentity {
	out := make([]TCPIdentity, len(tuples))
	wanted := map[tcpKey][]int{}
	for i, t := range tuples {
		key, ok := tcpTupleKey(t)
		if !ok {
			out[i].Err = ErrPeer
			continue
		}
		wanted[key] = append(wanted[key], i)
	}
	if len(wanted) == 0 {
		return out
	}
	found, err := readTCPTable(wanted)
	peers := map[tcpOwner]TCPIdentity{}
	for key, indexes := range wanted {
		owner, ok := found[key]
		for _, i := range indexes {
			switch {
			case err != nil:
				out[i].Err = err
			case !ok:
				out[i].Err = ErrPeer
			default:
				identity, cached := peers[owner]
				if !cached {
					peer, err := processPeerAt(owner.pid, owner.created)
					identity = TCPIdentity{User: peer.User, Err: err}
					peers[owner] = identity
				}
				out[i] = identity
			}
		}
	}
	return out
}

func tcpTupleKey(t TCPTuple) (tcpKey, bool) {
	if t.Client == nil || t.Server == nil || !t.Client.IP.IsLoopback() || !t.Server.IP.IsLoopback() {
		return tcpKey{}, false
	}
	client, server := t.Client.IP.To4(), t.Server.IP.To4()
	if client == nil || server == nil || t.Client.Port <= 0 || t.Client.Port > 0xffff || t.Server.Port <= 0 || t.Server.Port > 0xffff {
		return tcpKey{}, false
	}
	var key tcpKey
	copy(key.client[:], client)
	copy(key.server[:], server)
	key.clientPort, key.serverPort = uint16(t.Client.Port), uint16(t.Server.Port)
	return key, true
}

// readTCPTable reads TCP_TABLE_OWNER_MODULE_CONNECTIONS for its connection
// timestamps, which let processPeerAt reject a reused PID. Past the size
// limit it fails closed: the batch is unresolved, lands in the public pool
// and cannot pair. A table without timestamps cannot rule out a process
// created after the connection, so it is not used as a fallback.
func readTCPTable(wanted map[tcpKey][]int) (map[tcpKey]tcpOwner, error) {
	// MIB_TCPROW_OWNER_MODULE is 160 bytes aligned to eight. Its table
	// header has four bytes of padding before the first row on x64/ARM64.
	const header, rowSize = 8, 160
	words := make([]uint64, 8192)
	for range 5 {
		buffer := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
		size := uint32(len(buffer))
		code, _, _ := getTCPTable.Call(uintptr(unsafe.Pointer(&words[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 7, 0) // TCP_TABLE_OWNER_MODULE_CONNECTIONS
		if windows.Errno(code) == windows.ERROR_INSUFFICIENT_BUFFER {
			if size > 32<<20 {
				return nil, errors.New("TCP owner table exceeds limit")
			}
			words = make([]uint64, (size+4096+7)/8)
			continue
		}
		if code != 0 {
			return nil, windows.Errno(code)
		}
		if size < header || int(size) > len(buffer) {
			return nil, ErrPeer
		}
		count := int(binary.LittleEndian.Uint32(buffer))
		if count > (int(size)-header)/rowSize {
			return nil, ErrPeer
		}
		found := map[tcpKey]tcpOwner{}
		for i := range count {
			row := buffer[header+i*rowSize : header+(i+1)*rowSize]
			if binary.LittleEndian.Uint32(row) != 5 { // MIB_TCP_STATE_ESTAB
				continue
			}
			var key tcpKey
			copy(key.client[:], row[4:8])
			key.clientPort = binary.BigEndian.Uint16(row[8:10])
			copy(key.server[:], row[12:16])
			key.serverPort = binary.BigEndian.Uint16(row[16:18])
			if _, ok := wanted[key]; !ok {
				continue
			}
			created := binary.LittleEndian.Uint64(row[24:32])
			if created == 0 {
				continue // a row without a timestamp is not an identity
			}
			found[key] = tcpOwner{pid: binary.LittleEndian.Uint32(row[20:24]), created: created}
		}
		return found, nil
	}
	return nil, errors.New("TCP owner table kept changing")
}
