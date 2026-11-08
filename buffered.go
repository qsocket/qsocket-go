package qsocket

import (
	"bufio"
	"net"
)

// bufferedConn is a net.Conn whose reads go through a bufio.Reader.
//
// The knock response, the SRP messages and the encrypted stream are all read
// through the same buffer, so bytes that arrive together with an earlier
// message (the first SRP message of the peer is forwarded right after the
// protocol switch response) are never lost. Writes go to the connection
// directly.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads from the buffer first and the connection after it.
func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}
