package localipc

import (
	"encoding/binary"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// TCPOwner asks sock_diag for the exact client tuple. No /proc scan or PID
// inference is involved; the kernel supplies the socket's owning UID.
func TCPOwner(client, server *net.TCPAddr) (string, error) {
	if client.IP.To4() == nil || server.IP.To4() == nil || !client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return "", ErrPeer
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 250000}); err != nil {
		return "", err
	}
	request := make([]byte, 72) // nlmsghdr + inet_diag_req_v2
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], 20) // SOCK_DIAG_BY_FAMILY
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], 1)
	request[16], request[17] = unix.AF_INET, unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(request[20:], 1<<1) // TCP_ESTABLISHED
	binary.BigEndian.PutUint16(request[24:], uint16(client.Port))
	binary.BigEndian.PutUint16(request[26:], uint16(server.Port))
	copy(request[28:32], client.IP.To4())
	copy(request[44:48], server.IP.To4())
	binary.NativeEndian.PutUint32(request[64:], ^uint32(0))
	binary.NativeEndian.PutUint32(request[68:], ^uint32(0))
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return "", err
	}
	response := make([]byte, 4096)
	n, from, err := unix.Recvfrom(fd, response, 0)
	if err != nil {
		return "", err
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok || sender.Pid != 0 || n < 88 || binary.NativeEndian.Uint16(response[4:]) != 20 ||
		binary.NativeEndian.Uint32(response[8:]) != 1 || binary.NativeEndian.Uint32(response) > uint32(n) {
		return "", ErrPeer
	}
	body := response[16:n]
	if body[0] != unix.AF_INET || body[1] != 1 ||
		int(binary.BigEndian.Uint16(body[4:])) != client.Port || int(binary.BigEndian.Uint16(body[6:])) != server.Port ||
		!net.IP(body[8:12]).Equal(client.IP) || !net.IP(body[24:28]).Equal(server.IP) {
		return "", ErrPeer
	}
	return strconv.FormatUint(uint64(binary.NativeEndian.Uint32(body[64:])), 10), nil
}
