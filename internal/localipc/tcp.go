//go:build linux || windows

package localipc

import (
	"net"
	"time"
)

// TCPTuple is one accepted loopback connection, seen from the server side.
// Accepted is when the server accepted it, so the connection is older.
type TCPTuple struct {
	Client, Server *net.TCPAddr
	Accepted       time.Time
}

// TCPIdentity is the OS user owning a tuple's client end, or why it has none.
type TCPIdentity struct {
	User string
	Err  error
}

// TCPOwner resolves a single established loopback connection.
func TCPOwner(client, server *net.TCPAddr) (string, error) {
	identity := TCPOwners([]TCPTuple{{Client: client, Server: server, Accepted: time.Now()}})[0]
	return identity.User, identity.Err
}
