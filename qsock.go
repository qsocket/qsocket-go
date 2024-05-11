package qsocket

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	stream "github.com/qsocket/encrypted-stream"
	"golang.org/x/net/proxy"
)

const (
	// Tag ID for representing server mode connections.
	PEER_SRV = iota // 00000000 => Server
	// Tag ID for representing client mode connections.
	PEER_CLI
	// =====================================================================

	SRP_BITS = 4096
)

var (
	ErrUntrustedCert          = errors.New("Certificate fingerprint mismatch!")
	ErrUninitializedSocket    = errors.New("Socket not initiated,")
	ErrQSocketSessionEnd      = errors.New("QSocket session has ended.")
	ErrUnexpectedSocket       = errors.New("Unexpected socket type.")
	ErrInvalidIdTag           = errors.New("Invalid peer ID tag.")
	ErrNoTlsConnection        = errors.New("TLS socket is nil.")
	ErrSocketNotConnected     = errors.New("Socket is not connected.")
	ErrSrpFailed              = errors.New("SRP auth failed.")
	ErrSocketInUse            = errors.New("Socket already dialed.")
	ErrInvalidCertFingerprint = errors.New("Invalid TLS certificate fingerprint.")
	//
	TOR_MODE = false
)

// A QSocket structure contains required values
// for performing a knock sequence with the QSRN gate.
//
// `Secret` value can be considered as the password for the QSocket connection,
// It will be used for generating a 128bit unique identifier (UID) for the connection.
//
// `*tag` values are used internally for QoS purposes.
// It specifies the operating system, architecture and the type of connection initiated by the peers,
// the relay server uses these values for optimizing the connection performance.
type QSocket struct {
	secret   string
	certHash []byte
	e2e      bool
	peerTag  byte

	conn        net.Conn
	tlsConn     *tls.Conn
	encConn     *stream.EncryptedStream
	proxyDialer proxy.Dialer
}

// NewSocket creates a new QSocket structure with the given secret.
// `certVerify` value is used for enabling the certificate validation on TLS connections
func NewSocket(secret string) *QSocket {
	return &QSocket{
		secret:      secret,
		e2e:         true,
		conn:        nil,
		tlsConn:     nil,
		encConn:     nil,
		proxyDialer: nil,
	}
}

// AddIdTag adds a peer identification tag to the QSocket.
func (qs *QSocket) SetIdTag(idTag byte) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	switch idTag {
	case PEER_SRV, PEER_CLI:
		qs.peerTag = idTag
	default:
		return ErrInvalidIdTag
	}
	return nil
}

// AddIdTag adds a peer identification tag to the QSocket.
func (qs *QSocket) SetE2E(v bool) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	qs.e2e = v
	return nil
}

// AddIdTag adds a peer identification tag to the QSocket.
func (qs *QSocket) SetCertFingerprint(h string) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	hash, err := hex.DecodeString(h)
	if err != nil {
		return err
	}
	if len(hash) != 32 {
		return ErrInvalidCertFingerprint
	}

	qs.certHash = hash
	return nil
}

// AddIdTag adds a peer identification tag to the QSocket.
func (qs *QSocket) SetProxy(proxyAddr string) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	if proxyAddr == "127.0.0.1:9050" {
		TOR_MODE = true
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil,
		&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		},
	)
	if err != nil {
		return err
	}
	qs.proxyDialer = dialer
	return nil
}

// DialTCP creates a TCP connection to the `QSRN_GATE` on `QSRN_GATE_PORT`.
func (qs *QSocket) DialTCP() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", QSRN_GATE, QSRN_GATE_PORT))
	if err != nil {
		return err
	}
	qs.conn = conn

	if qs.proxyDialer != nil {
		gate := QSRN_GATE
		if TOR_MODE {
			gate = QSRN_TOR_GATE
		}
		pConn, err := qs.proxyDialer.Dial("tcp", fmt.Sprintf("%s:%d", gate, QSRN_GATE_PORT))
		if err != nil {
			return err
		}
		qs.conn = pConn
	}

	return qs.InitiateKnockSequence()
}

// Dial creates a TLS connection to the `QSRN_GATE` on `QSRN_GATE_TLS_PORT`.
// Based on the `VerifyCert` parameter, certificate fingerprint validation (a.k.a. SSL pinning)
// will be performed after establishing the TLS connection.
func (qs *QSocket) Dial() error {
	if qs.proxyDialer != nil {
		gate := QSRN_GATE
		if TOR_MODE {
			gate = QSRN_TOR_GATE
		}
		pConn, err := qs.proxyDialer.Dial("tcp", fmt.Sprintf("%s:%d", gate, QSRN_GATE_TLS_PORT))
		if err != nil {
			return err
		}
		qs.conn = pConn
	} else {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", QSRN_GATE, QSRN_GATE_TLS_PORT))
		if err != nil {
			return err
		}
		qs.conn = conn
	}
	qs.tlsConn = tls.Client(qs.conn, &tls.Config{InsecureSkipVerify: true})

	err := qs.VerifyTlsCertificate()
	if err != nil {
		return err
	}

	return qs.InitiateKnockSequence()
}

func (qs *QSocket) VerifyTlsCertificate() error {
	if qs.IsClosed() {
		return ErrSocketNotConnected
	}

	if qs.tlsConn == nil {
		return ErrNoTlsConnection
	}

	if qs.certHash == nil {
		return nil
	}

	connState := qs.tlsConn.ConnectionState()
	for _, peerCert := range connState.PeerCertificates {
		hash := sha256.Sum256(peerCert.Raw)
		if !bytes.Equal(hash[0:], qs.certHash) {
			return ErrUntrustedCert
		}
	}
	return nil
}

// IsClient checks if the QSocket connection is initiated as a client or a server.
func (qs *QSocket) IsClient() bool {
	return qs.peerTag == PEER_CLI
}

// IsClient checks if the QSocket connection is initiated as a client or a server.
func (qs *QSocket) IsServer() bool {
	return !qs.IsClient()
}

// IsClosed checks if the QSocket connection to the `QSRN_GATE` is ended.
func (qs *QSocket) IsClosed() bool {
	return qs.conn == nil && qs.tlsConn == nil && qs.encConn == nil
}

// IsTLS checks if the underlying connection is TLS or not.
func (qs *QSocket) IsTLS() bool {
	return qs.tlsConn != nil
}

// IsE2E checks if the underlying connection is E2E encrypted or not.
func (qs *QSocket) IsE2E() bool {
	return qs.encConn != nil && qs.e2e
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (qs *QSocket) SetReadDeadline(t time.Time) error {
	if qs.IsTLS() {
		return qs.tlsConn.SetReadDeadline(t)
	}
	if qs.conn != nil {
		return qs.conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
// Even if write times out, it may return n > 0, indicating that some of the data was successfully written. A zero value for t means Write will not time out.
func (qs *QSocket) SetWriteDeadline(t time.Time) error {
	if qs.IsTLS() {
		return qs.tlsConn.SetWriteDeadline(t)
	}
	if qs.conn != nil {
		return qs.conn.SetWriteDeadline(t)
	}
	return nil
}

// RemoteAddr returns the remote network address.
func (qs *QSocket) RemoteAddr() net.Addr {
	if qs.IsTLS() {
		return qs.tlsConn.RemoteAddr()
	}
	if qs.conn != nil {
		return qs.conn.RemoteAddr()
	}
	return nil
}

// LocalAddr returns the local network address.
func (qs *QSocket) LocalAddr() net.Addr {
	if qs.IsTLS() {
		return qs.tlsConn.LocalAddr()
	}
	if qs.conn != nil {
		return qs.conn.LocalAddr()
	}
	return nil
}

// Read reads data from the connection.
//
// As Read calls Handshake, in order to prevent indefinite blocking a deadline must be set for both Read and Write before Read is called when the handshake has not yet completed.
// See SetDeadline, SetReadDeadline, and SetWriteDeadline.
func (qs *QSocket) Read(b []byte) (int, error) {
	if qs.IsE2E() {
		return qs.encConn.Read(b)
	}
	if qs.IsTLS() {
		return qs.tlsConn.Read(b)
	}
	if qs.conn != nil {
		return qs.conn.Read(b)
	}
	return 0, ErrUninitializedSocket
}

// Write writes data to the connection.
//
// As Write calls Handshake, in order to prevent indefinite blocking a deadline must be set for both Read and Write before Write is called when the handshake has not yet completed.
// See SetDeadline, SetReadDeadline, and SetWriteDeadline.
func (qs *QSocket) Write(b []byte) (int, error) {
	if qs.IsE2E() {
		return qs.encConn.Write(b)
	}
	if qs.tlsConn != nil {
		return qs.tlsConn.Write(b)
	}
	if qs.conn != nil {
		return qs.conn.Write(b)
	}
	return 0, ErrUninitializedSocket
}

// Close closes the QSocket connection and underlying TCP/TLS connections.
func (qs *QSocket) Close() {
	if qs.encConn != nil {
		qs.encConn.Close()
	}
	if qs.tlsConn != nil {
		qs.tlsConn.Close()
	}
	if qs.conn != nil {
		qs.conn.Close()
	}
	qs.conn = nil
	qs.tlsConn = nil
	qs.encConn = nil
}

// chanFromConn creates a channel from a Conn object, and sends everything it
//
//	Read()s from the socket to the channel.
func CreateSocketChan(sock *QSocket) chan []byte {
	c := make(chan []byte)

	go func() {
		b := make([]byte, 1024)
		for {
			if sock.IsClosed() {
				c <- nil
				return
			}
			sock.SetReadDeadline(time.Time{})
			n, err := sock.Read(b)
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil || sock.IsClosed() {
				// if err.Error() != "EOF" {
				// 	logrus.Errorf("%s -read-err-> %s", sock.RemoteAddr(), err)
				// }
				c <- nil
				break
			}
		}
	}()

	return c
}

// BindSockets is used for creating a full duplex channel between `con1` and `con2` sockets,
// effectively binding two sockets.
func BindSockets(con1, con2 *QSocket) error {
	defer con1.Close()
	defer con2.Close()
	chan1 := CreateSocketChan(con1)
	chan2 := CreateSocketChan(con2)
	var err error
	for {
		select {
		case b1 := <-chan1:
			if b1 != nil {
				_, err = con2.Write(b1)
			} else {
				err = ErrQSocketSessionEnd
			}
		case b2 := <-chan2:
			if b2 != nil {
				_, err = con1.Write(b2)
			} else {
				err = ErrQSocketSessionEnd
			}
		}
		if err != nil {
			break
		}
	}
	return err
}
