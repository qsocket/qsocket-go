package qsocket

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	stream "github.com/qsocket/encrypted-stream"
	"golang.org/x/net/proxy"
)

const (
	// TAG_OS_UNKNOWN Tag ID value representing connections from UNKNOWN devices.
	TAG_OS_UNKNOWN = iota
	// TAG_OS_LINUX Tag ID value representing connections from LINUX devices.
	TAG_OS_LINUX
	// TAG_OS_DARWIN Tag ID value representing connections from DARWIN devices.
	TAG_OS_DARWIN
	// TAG_OS_WINDOWS Tag ID value representing connections from WINDOWS devices.
	TAG_OS_WINDOWS
	// TAG_OS_ANDROID Tag ID value representing connections from ANDROID devices.
	TAG_OS_ANDROID
	// TAG_OS_IOS Tag ID value representing connections from IOS devices.
	TAG_OS_IOS
	// TAG_OS_FREEBSD Tag ID value representing connections from FREEBSD devices.
	TAG_OS_FREEBSD
	// TAG_OS_OPENBSD Tag ID value representing connections from OPENBSD devices.
	TAG_OS_OPENBSD
	// TAG_OS_NETBSD Tag ID value representing connections from NETBSD devices.
	TAG_OS_NETBSD
	// TAG_OS_JS Tag ID value representing connections from JavaScript engines.
	TAG_OS_JS
	// TAG_OS_SOLARIS Tag ID value representing connections from SOLARIS devices.
	TAG_OS_SOLARIS
	// TAG_OS_DRAGONFLY Tag ID value representing connections from DRAGONFLY devices.
	TAG_OS_DRAGONFLY
	// TAG_OS_ILLUMOS Tag ID value representing connections from ILLUMOS devices.
	TAG_OS_ILLUMOS
	// TAG_OS_AIX Tag ID value representing connections from AIX devices.
	TAG_OS_AIX
	// TAG_OS_ZOS Tag ID value representing connections from ZOS devices.
	TAG_OS_ZOS
	// TAG_OS_NACL Tag ID value representing connections from NACL devices.
	TAG_OS_NACL
	// TAG_OS_PLAN9 Tag ID value representing connections from PLAN9 devices.
	TAG_OS_PLAN9
	// TAG_OS_HURD Tag ID value representing connections from HURD devices.
	TAG_OS_HURD
)

const (
	// TAG_ARCH_UNKNOWN Tag ID value representing connections from devices with UNKNOWN architecture.
	TAG_ARCH_UNKNOWN = iota // 11100000 => UNKNOWN
	// TAG_ARCH_386 Tag ID value representing connections from devices with 386 architecture.
	TAG_ARCH_386
	// TAG_ARCH_AMD64 Tag ID value representing connections from devices with AMD64 architecture.
	TAG_ARCH_AMD64
	// TAG_ARCH_AMD64P32 Tag ID value representing connections from devices with AMD64 architecture.
	TAG_ARCH_AMD64P32
	// TAG_ARCH_ARM64 Tag ID value representing connections from devices with ARM64 architecture.
	TAG_ARCH_ARM64
	// TAG_ARCH_ARM64P32 Tag ID value representing connections from devices with ARM64BE architecture.
	TAG_ARCH_ARM64BE
	// TAG_ARCH_ARM Tag ID value representing connections from devices with ARM architecture.
	TAG_ARCH_ARM
	// TAG_ARCH_ARMBE Tag ID value representing connections from devices with ARMBE architecture.
	TAG_ARCH_ARMBE
	// TAG_ARCH_LOONG64 Tag ID value representing connections from devices with LOONG64 architecture.
	TAG_ARCH_LOONG64
	// TAG_ARCH_MIPS Tag ID value representing connections from devices with MIPS architecture.
	TAG_ARCH_MIPS
	// TAG_ARCH_MIPSLE Tag ID value representing connections from devices with MIPS architecture.
	TAG_ARCH_MIPSLE
	// TAG_ARCH_MIPS64 Tag ID value representing connections from devices with MIPS64 architecture.
	TAG_ARCH_MIPS64
	// TAG_ARCH_MIPS64LE Tag ID value representing connections from devices with MIPS64LE architecture.
	TAG_ARCH_MIPS64LE
	// TAG_ARCH_MIPS64P32 Tag ID value representing connections from devices with MIPS64P32 architecture.
	TAG_ARCH_MIPS64P32
	// TAG_ARCH_MIPS64P32LE Tag ID value representing connections from devices with MIPS64P32LE architecture.
	TAG_ARCH_MIPS64P32LE
	// TAG_ARCH_PPC Tag ID value representing connections from devices with PPC architecture.
	TAG_ARCH_PPC
	// TAG_ARCH_PPC64 Tag ID value representing connections from devices with PPC64 architecture.
	TAG_ARCH_PPC64
	// TAG_ARCH_PPC64LE Tag ID value representing connections from devices with PPC64LE architecture.
	TAG_ARCH_PPC64LE
	// TAG_ARCH_RISCV Tag ID value representing connections from devices with RISCV architecture.
	TAG_ARCH_RISCV
	// TAG_ARCH_RISCV64 Tag ID value representing connections from devices with RISCV64 architecture.
	TAG_ARCH_RISCV64
	// TAG_ARCH_S390 Tag ID value representing connections from devices with S390 architecture.
	TAG_ARCH_S390
	// TAG_ARCH_S390X Tag ID value representing connections from devices with S390X architecture.
	TAG_ARCH_S390X
	// TAG_ARCH_SPARC Tag ID value representing connections from devices with SPARC architecture.
	TAG_ARCH_SPARC
	// TAG_ARCH_SPARC64 Tag ID value representing connections from devices with SPARC64 architecture.
	TAG_ARCH_SPARC64
	// WASM Tag ID value representing connections from devices with WASM architecture.
	TAG_ARCH_WASM
)

const (
	// Tag ID for representing server mode connections.
	TAG_PEER_SRV = iota // 00000000 => Server
	// Tag ID for representing client mode connections.
	TAG_PEER_CLI
	// TAG_PEER_PROXY Tag ID for representing proxy mode connections.
	TAG_PEER_PROXY
	// =====================================================================

	SRP_BITS = 4096
)

var (
	ErrUntrustedCert       = errors.New("certificate fingerprint mismatch")
	ErrUninitializedSocket = errors.New("socket not initiated")
	ErrQSocketSessionEnd   = errors.New("QSocket session has ended")
	ErrUnexpectedSocket    = errors.New("unexpected socket type")
	ErrInvalidIdTag        = errors.New("invalid peer ID tag")
	ErrNoTlsConnection     = errors.New("TLS socket is nil")
	ErrSocketNotConnected  = errors.New("socket is not connected")
	ErrSrpFailed           = errors.New("SRP auth failed")
	ErrSocketInUse         = errors.New("socket already dialed")
	ErrAddressInUse        = errors.New("address already in use")
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
	secret     string
	certVerify bool
	e2e        bool
	forward    string
	archTag    byte
	osTag      byte
	peerTag    byte
	conn       net.Conn
	tlsConn    *tls.Conn
	encConn    *stream.EncryptedStream
}

// NewSocket creates a new QSocket structure with the given secret.
// `certVerify` value is used for enabling the certificate validation on TLS connections
func NewSocket(secret string) *QSocket {
	return &QSocket{
		secret:  secret,
		osTag:   GetOsTag(),
		archTag: GetArchTag(),
		e2e:     true,
		conn:    nil,
		tlsConn: nil,
		encConn: nil,
	}
}

func (qs *QSocket) SetForwardAddr(addr string) {
	qs.forward = addr
}

func (qs *QSocket) GetForwardAddr() string {
	return qs.forward
}

// AddIdTag adds a peer identification tag to the QSocket.
func (qs *QSocket) AddIdTag(idTag byte) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	switch idTag {
	case TAG_PEER_SRV:
		qs.peerTag |= idTag
	case TAG_PEER_CLI:
		qs.peerTag |= idTag
	case TAG_PEER_PROXY:
		qs.peerTag |= idTag
	case TAG_PEER_PROXY | TAG_PEER_CLI:
		qs.peerTag |= idTag
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
func (qs *QSocket) SetCertPinning(v bool) error {
	if !qs.IsClosed() {
		return ErrSocketInUse
	}

	qs.certVerify = v
	return nil
}

// DialTCP creates a TCP connection to the `QSRN_GATE` on `QSRN_GATE_PORT`.
func (qs *QSocket) DialTCP() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", QSRN_GATE, QSRN_GATE_PORT))
	if err != nil {
		return err
	}
	qs.conn = conn
	resp, err := qs.SendKnockSequence()
	if err != nil {
		return err
	}
	if resp.Success {
		if resp.Forward {
			qs.forward = string(resp.Data)
		}
		return nil
	}
	return ErrConnRefused
}

// Dial creates a TLS connection to the `QSRN_GATE` on `QSRN_GATE_TLS_PORT`.
// Based on the `VerifyCert` parameter, certificate fingerprint validation (a.k.a. SSL pinning)
// will be performed after establishing the TLS connection.
func (qs *QSocket) Dial() error {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", QSRN_GATE, QSRN_GATE_TLS_PORT), conf)
	if err != nil {
		return err
	}
	qs.tlsConn = conn

	if qs.certVerify {
		connState := conn.ConnectionState()
		for _, peerCert := range connState.PeerCertificates {
			hash := sha256.Sum256(peerCert.Raw)
			if !bytes.Equal(hash[0:], []byte(CERT_FINGERPRINT)) {
				return ErrUntrustedCert
			}
		}
	}

	resp, err := qs.SendKnockSequence()
	if err != nil {
		return err
	}

	if !resp.Success {
		return ErrConnRefused
	}

	if resp.Forward && qs.IsServer() {
		qs.forward = string(resp.Data)
	}

	if !qs.e2e {
		return nil
	}

	sessionKey := []byte{}
	if qs.IsClient() {
		sessionKey, err = qs.InitClientSRP()
	} else {
		sessionKey, err = qs.InitServerSRP()
	}
	if err != nil {
		return err
	}

	return qs.InitE2ECipher(sessionKey)
}

// DialProxy tries to create TCP connection to the `QSRN_GATE` using a SOCKS5 proxy.
// `proxyAddr` should contain a valid SOCKS5 proxy.
func (qs *QSocket) DialProxy(proxyAddr string) error {
	proxyDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil,
		&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		},
	)
	if err != nil {
		return err
	}

	conn, err := proxyDialer.Dial("tcp", fmt.Sprintf("%s:%d", QSRN_GATE, QSRN_GATE_PORT))
	if err != nil {
		return err
	}
	qs.conn = conn
	resp, err := qs.SendKnockSequence()
	if err != nil {
		return err
	}

	if !resp.Success {
		return ErrConnRefused
	}

	if resp.Forward {
		qs.forward = string(resp.Data)
	}

	if !qs.e2e {
		return nil
	}

	sessionKey := []byte{}
	if qs.IsClient() {
		sessionKey, err = qs.InitClientSRP()
	} else {
		sessionKey, err = qs.InitServerSRP()
	}
	if err != nil {
		return err
	}

	return qs.InitE2ECipher(sessionKey)
}

// IsClient checks if the QSocket connection is initiated as a client or a server.
func (qs *QSocket) IsClient() bool {
	return (qs.peerTag%2 == 1)
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
