package qsocket

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"time"

	stream "github.com/qsocket/encrypted-stream"
	"golang.org/x/net/proxy"
)

const (
	// Tag ID for representing server mode connections.
	Server SocketType = iota // 00000000 => Server
	// Tag ID for representing client mode connections.
	Client
	// =====================================================================
)

var (
	Version                   = "0.1.0"
	ErrNoTransport            = errors.New("Socket transport is not initialized.")
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
	TOR_MODE      = false
	QSRN_GATE_SNI = QSRN_GATE
)

type SocketType byte

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
	secret       string
	certHash     []byte
	insecureCert bool
	e2e          bool
	socketType   SocketType

	conn        net.Conn
	tlsConn     *tls.Conn
	encConn     *stream.EncryptedStream
	proxyDialer proxy.Dialer

	// transport is the connection the knock and the session run over, the
	// TLS connection when TLS is used and the TCP connection otherwise.
	transport net.Conn
	// reader buffers every read from the transport, see bufferedConn.
	reader *bufio.Reader
}

// transportBufferSize is the size of the read buffer over the transport, it
// holds a full TLS record.
const transportBufferSize = 16 * 1024

// NewSocket creates a new QSocket structure with the given secret.
// `certVerify` value is used for enabling the certificate validation on TLS connections
func NewSocket(sType SocketType, secret string) *QSocket {
	switch sType {
	case Client, Server:
	default:
		panic("Invalid socket type!")
	}

	return &QSocket{
		secret:      secret,
		socketType:  sType,
		e2e:         true,
		conn:        nil,
		tlsConn:     nil,
		encConn:     nil,
		proxyDialer: nil,
	}
}

// AddIdTag adds a peer identification tag to the QSocket.
func (qs *QSocket) SetE2E(v bool) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	qs.e2e = v
	return nil
}

// SetCertFingerprint pins the TLS certificate of the gate.
//
// h is the hex encoded SHA-256 hash of the SubjectPublicKeyInfo (SPKI) of the
// gate's leaf certificate. When set, the pin replaces the CA validation: the
// gate is accepted if and only if the public key of its certificate matches,
// so gates with self signed certificates can be used. The TLS handshake
// signature is still verified, so the gate must hold the matching private key.
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

// SetInsecureCert disables the TLS certificate validation of the gate when no
// certificate fingerprint is pinned. Any certificate is accepted, so the
// identity of the gate is not checked at all. A pinned fingerprint takes
// precedence over this setting.
func (qs *QSocket) SetInsecureCert(v bool) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	qs.insecureCert = v
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

// Dial creates a TLS connection to the `QSRN_GATE` on `QSRN_GATE_TLS_PORT`.
// The TLS handshake is completed before the knock sequence is sent, so a
// certificate that fails the validation (or the pinned fingerprint, see
// SetCertFingerprint) ends the connection before any knock byte is written.
func (qs *QSocket) Dial(useTls bool) error {
	port := QSRN_GATE_PORT
	gate := QSRN_GATE

	if useTls {
		port = QSRN_GATE_TLS_PORT
	}
	if TOR_MODE {
		gate = QSRN_TOR_GATE
	}

	if qs.proxyDialer != nil {
		pConn, err := qs.proxyDialer.Dial("tcp", net.JoinHostPort(gate, strconv.Itoa(port)))
		if err != nil {
			return err
		}
		qs.conn = pConn
	} else {
		conn, err := net.Dial("tcp", net.JoinHostPort(QSRN_GATE, strconv.Itoa(port)))
		if err != nil {
			return err
		}
		qs.conn = conn
	}

	qs.transport = qs.conn
	if useTls {
		qs.tlsConn = tls.Client(qs.conn, qs.tlsConfig())
		if err := qs.tlsConn.Handshake(); err != nil {
			qs.Close()
			return err
		}
		qs.transport = qs.tlsConn
	}
	qs.reader = bufio.NewReaderSize(qs.transport, transportBufferSize)

	if err := qs.InitKnockSequence(); err != nil {
		qs.Close()
		return err
	}
	return nil
}

// tlsConfig returns the TLS client configuration of the socket.
//
// Without a pinned fingerprint or the insecure flag the gate certificate is
// validated against the system roots, as usual.
func (qs *QSocket) tlsConfig() *tls.Config {
	conf := &tls.Config{
		ServerName: QSRN_GATE_SNI,
		// A browser opening a WebSocket over HTTP/1.1 offers this.
		NextProtos: []string{"http/1.1"},
	}

	if qs.certHash != nil {
		pin := qs.certHash
		// The chain validation is turned off on purpose, the pinned
		// fingerprint given by the user replaces it, which is what allows
		// gates with self signed certificates. crypto/tls still verifies
		// the handshake signature against the leaf certificate key, and
		// VerifyConnection below only accepts the pinned key.
		conf.InsecureSkipVerify = true
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrUntrustedCert
			}
			hash := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(hash[:], pin) != 1 {
				return ErrUntrustedCert
			}
			return nil
		}
		return conf
	}

	if qs.insecureCert {
		// The certificate validation is turned off on purpose, only on
		// the explicit request of the user (--insecure-cert). The identity
		// of the gate is not checked.
		conf.InsecureSkipVerify = true
	}
	return conf
}

// IsClient checks if the QSocket connection is initiated as a client or a server.
func (qs *QSocket) IsClient() bool {
	return qs.socketType == Client
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
	if qs.reader != nil {
		return qs.reader.Read(b)
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
	if qs.transport != nil {
		return qs.transport.Write(b)
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
	qs.transport = nil
	qs.reader = nil
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
