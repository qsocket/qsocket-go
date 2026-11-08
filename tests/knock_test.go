package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qsocket/qsocket-go"
)

// The tests point the package level gate settings at a fake gate listening
// on the loopback interface, they must not run in parallel.

type gateSettings struct {
	gate, sni     string
	port, tlsPort int
	torMode       bool
}

func saveGate() gateSettings {
	return gateSettings{
		qsocket.QSRN_GATE, qsocket.QSRN_GATE_SNI,
		qsocket.QSRN_GATE_PORT, qsocket.QSRN_GATE_TLS_PORT, qsocket.TOR_MODE,
	}
}

func (g gateSettings) restore() {
	qsocket.QSRN_GATE = g.gate
	qsocket.QSRN_GATE_SNI = g.sni
	qsocket.QSRN_GATE_PORT = g.port
	qsocket.QSRN_GATE_TLS_PORT = g.tlsPort
	qsocket.TOR_MODE = g.torMode
}

// useGate points the library at the given loopback listener.
func useGate(t *testing.T, ln net.Listener) {
	t.Helper()
	saved := saveGate()
	t.Cleanup(saved.restore)
	port := ln.Addr().(*net.TCPAddr).Port
	qsocket.QSRN_GATE = "127.0.0.1"
	qsocket.QSRN_GATE_SNI = "127.0.0.1"
	qsocket.QSRN_GATE_PORT = port
	qsocket.QSRN_GATE_TLS_PORT = port
	qsocket.TOR_MODE = false
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// readKnock reads one knock request header block.
func readKnock(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		b.WriteString(line)
		if err != nil {
			return b.String(), err
		}
		if line == "\r\n" {
			return b.String(), nil
		}
	}
}

func knockPath(req string) string {
	first := strings.SplitN(req, "\r\n", 2)[0]
	f := strings.Fields(first)
	if len(f) < 2 {
		return ""
	}
	return strings.TrimPrefix(f[1], "/")
}

func knockRole(req string) qsocket.SocketType {
	return qsocket.SocketType(qsocket.CalcChecksum([]byte(knockPath(req)), qsocket.CHECKSUM_BASE))
}

func headerValue(req, name string) string {
	for _, line := range strings.Split(req, "\r\n") {
		k, v, ok := strings.Cut(line, ": ")
		if ok && strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func TestKnockRequestMatchesVector(t *testing.T) {
	vector, err := os.ReadFile("testdata/knock.txt")
	if err != nil {
		t.Fatal(err)
	}
	const (
		path = "aB3"
		host = "relay.qsocket.io"
		ua   = "Mozilla/5.0 (LINUX; AMD64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.1.0 Safari/537.36"
		key  = "jYMeCEUPoOfoQwmg1LxkTg=="
	)
	want := strings.NewReplacer("{PATH}", path, "{HOST}", host, "{UA}", ua, "{KEY}", key).Replace(string(vector))
	got := qsocket.KnockRequest(path, host, "https://"+host, ua, key)
	if got != want {
		t.Fatalf("knock request does not match testdata/knock.txt\ngot:\n%q\nwant:\n%q", got, want)
	}
	for i, line := range strings.SplitAfter(got, "\n") {
		if line != "" && !strings.HasSuffix(line, "\r\n") {
			t.Errorf("line %d does not end with CRLF: %q", i, line)
		}
	}
}

// serveOnce accepts one connection on ln, reads the knock and answers it
// with resp, written in a single write.
func serveOnce(t *testing.T, ln net.Listener, resp string) <-chan string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer c.Close()
		req, _ := readKnock(bufio.NewReader(c))
		got <- req
		c.Write([]byte(resp))
		// Keep the connection open until the client is done with it.
		io.Copy(io.Discard, c)
	}()
	return got
}

func TestPlainKnockKeepsBytesAfterSwitch(t *testing.T) {
	ln := listen(t)
	useGate(t, ln)
	payload := strings.Repeat("first-peer-message.", 16)
	reqCh := serveOnce(t, ln,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: x\r\n\r\n"+payload)

	qs := qsocket.NewSocket(qsocket.Server, "example-secret")
	qs.SetE2E(false)
	if err := qs.Dial(false); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer qs.Close()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(qs, buf); err != nil {
		t.Fatalf("reading the bytes sent with the 101: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("got %q, want %q", buf, payload)
	}

	req := <-reqCh
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if h := headerValue(req, "Host"); h != "127.0.0.1:"+port {
		t.Errorf("Host = %q", h)
	}
	if o := headerValue(req, "Origin"); o != "http://127.0.0.1:"+port {
		t.Errorf("Origin = %q", o)
	}
	if knockRole(req) != qsocket.Server {
		t.Errorf("request path %q does not carry the server role", knockPath(req))
	}
}

func TestKnockStatusCodes(t *testing.T) {
	cases := []struct {
		name string
		resp string
		want func(error) bool
	}{
		{"404", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
			func(err error) bool { return errors.Is(err, qsocket.ErrPeerNotFound) }},
		{"409", "HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n",
			func(err error) bool { return errors.Is(err, qsocket.ErrServerCollision) }},
		{"426 crlf body", "HTTP/1.1 426 Upgrade Required\r\nContent-Type: text/plain\r\nContent-Length: 22\r\n\r\nPlease update qsocket.",
			func(err error) bool { return err != nil && err.Error() == "Please update qsocket." }},
		{"426 lf body", "HTTP/1.1 426 Upgrade Required\nContent-Type: text/plain\n\nPlease update qsocket.",
			func(err error) bool { return err != nil && err.Error() == "Please update qsocket." }},
		{"426 no body", "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n",
			func(err error) bool { return errors.Is(err, qsocket.ErrUpgradeRequired) }},
		{"garbage", "SSH-2.0-OpenSSH\r\n\r\n",
			func(err error) bool { return errors.Is(err, qsocket.ErrInvalidProtocolSwitchResponse) }},
		{"oversized header", "HTTP/1.1 101 Switching Protocols\r\nX-Pad: " + strings.Repeat("a", 17*1024) + "\r\n\r\n",
			func(err error) bool { return errors.Is(err, qsocket.ErrInvalidProtocolSwitchResponse) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln := listen(t)
			useGate(t, ln)
			serveOnce(t, ln, tc.resp)
			qs := qsocket.NewSocket(qsocket.Client, "example-secret")
			qs.SetE2E(false)
			err := qs.Dial(false)
			if err == nil {
				qs.Close()
			}
			if !tc.want(err) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// selfSigned returns a self signed certificate for 127.0.0.1.
func selfSigned(t *testing.T) (tls.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gate.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, key
}

func spkiPin(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// tlsGate serves one TLS knock with a 101 response and reports the ALPN
// protocol negotiated with the client.
func tlsGate(t *testing.T, cert tls.Certificate) (net.Listener, <-chan string) {
	t.Helper()
	ln := listen(t)
	alpn := make(chan string, 1)
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := tls.Server(c, conf)
		if err := tc.Handshake(); err != nil {
			alpn <- ""
			return
		}
		alpn <- tc.ConnectionState().NegotiatedProtocol
		readKnock(bufio.NewReader(tc))
		tc.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		io.Copy(io.Discard, tc)
	}()
	return ln, alpn
}

func dialTLS(t *testing.T, ln net.Listener, setup func(*qsocket.QSocket) error) error {
	t.Helper()
	useGate(t, ln)
	qs := qsocket.NewSocket(qsocket.Client, "example-secret")
	qs.SetE2E(false)
	if err := setup(qs); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := qs.Dial(true)
	if err == nil {
		qs.Close()
	}
	return err
}

func TestCertificateModes(t *testing.T) {
	cert, _ := selfSigned(t)
	other, _ := selfSigned(t)

	t.Run("pinned", func(t *testing.T) {
		ln, alpn := tlsGate(t, cert)
		if err := dialTLS(t, ln, func(qs *qsocket.QSocket) error {
			return qs.SetCertFingerprint(spkiPin(cert))
		}); err != nil {
			t.Fatalf("pinned self signed gate refused: %v", err)
		}
		if p := <-alpn; p != "http/1.1" {
			t.Errorf("negotiated ALPN %q, want http/1.1", p)
		}
	})

	t.Run("wrong pin", func(t *testing.T) {
		ln, _ := tlsGate(t, cert)
		err := dialTLS(t, ln, func(qs *qsocket.QSocket) error {
			return qs.SetCertFingerprint(spkiPin(other))
		})
		if !errors.Is(err, qsocket.ErrUntrustedCert) {
			t.Fatalf("got %v, want %v", err, qsocket.ErrUntrustedCert)
		}
	})

	t.Run("pin with a key the gate does not hold", func(t *testing.T) {
		// The gate presents the pinned certificate but signs the handshake
		// with another key, the handshake signature check must catch it.
		_, otherKey := selfSigned(t)
		forged := tls.Certificate{Certificate: cert.Certificate, PrivateKey: otherKey, Leaf: cert.Leaf}
		ln, _ := tlsGate(t, forged)
		err := dialTLS(t, ln, func(qs *qsocket.QSocket) error {
			return qs.SetCertFingerprint(spkiPin(cert))
		})
		if err == nil {
			t.Fatal("handshake signed with a different key was accepted")
		}
	})

	t.Run("insecure", func(t *testing.T) {
		ln, _ := tlsGate(t, cert)
		if err := dialTLS(t, ln, func(qs *qsocket.QSocket) error {
			return qs.SetInsecureCert(true)
		}); err != nil {
			t.Fatalf("insecure mode refused the gate: %v", err)
		}
	})

	t.Run("default rejects self signed", func(t *testing.T) {
		ln, _ := tlsGate(t, cert)
		err := dialTLS(t, ln, func(qs *qsocket.QSocket) error { return nil })
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Fatalf("got %v, want an unknown authority error", err)
		}
	})

	t.Run("invalid fingerprint", func(t *testing.T) {
		qs := qsocket.NewSocket(qsocket.Client, "example-secret")
		if err := qs.SetCertFingerprint("deadbeef"); !errors.Is(err, qsocket.ErrInvalidCertFingerprint) {
			t.Fatalf("got %v", err)
		}
	})
}

// relayGate is a minimal stand-in for the relay: it pairs one server and one
// client knock, answers both with a 101 and copies the bytes between them.
//
// The 101 of the server is held back until the first message of the client
// has arrived, then both are sent in a single write, which is the case that
// lost the client's first SRP message before.
func relayGate(t *testing.T, ln net.Listener, conf *tls.Config) {
	t.Helper()
	const resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	go func() {
		var srv, cli net.Conn
		var srvR, cliR *bufio.Reader
		for srv == nil || cli == nil {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if conf != nil {
				tc := tls.Server(c, conf)
				if err := tc.Handshake(); err != nil {
					c.Close()
					return
				}
				c = tc
			}
			r := bufio.NewReader(c)
			req, err := readKnock(r)
			if err != nil {
				c.Close()
				return
			}
			if knockRole(req) == qsocket.Server {
				srv, srvR = c, r
			} else {
				cli, cliR = c, r
			}
		}
		defer srv.Close()
		defer cli.Close()

		cli.Write([]byte(resp))
		first := make([]byte, 64*1024)
		n, err := cliR.Read(first)
		if err != nil {
			return
		}
		srv.Write(append([]byte(resp), first[:n]...))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { io.Copy(srv, cliR); closeWrite(srv); wg.Done() }()
		go func() { io.Copy(cli, srvR); closeWrite(cli); wg.Done() }()
		wg.Wait()
	}()
}

func closeWrite(c net.Conn) {
	switch v := c.(type) {
	case *net.TCPConn:
		v.CloseWrite()
	case *tls.Conn:
		v.CloseWrite()
	}
}

func TestPlainE2ESessionThroughRelay(t *testing.T) {
	// --no-tls with E2E on used to panic, the encrypted stream was built
	// over a nil TLS connection.
	runRelaySessions(t, false, 5)
}

func TestTLSE2ESessionThroughRelay(t *testing.T) {
	// Over TLS the relay's 101 and the client's first SRP message can share
	// one TLS record, a single read of the switch response used to swallow
	// the SRP message and hang the session.
	runRelaySessions(t, true, 5)
}

func runRelaySessions(t *testing.T, useTLS bool, sessions int) {
	t.Helper()
	var conf *tls.Config
	var pin string
	if useTLS {
		cert, _ := selfSigned(t)
		conf = &tls.Config{Certificates: []tls.Certificate{cert}}
		pin = spkiPin(cert)
	}
	for i := 0; i < sessions; i++ {
		ln := listen(t)
		useGate(t, ln)
		relayGate(t, ln, conf)
		newSocket := func(st qsocket.SocketType, secret string) *qsocket.QSocket {
			qs := qsocket.NewSocket(st, secret)
			if useTLS {
				qs.SetCertFingerprint(pin)
			}
			return qs
		}

		secret := "f81d4fae-7dec-41d0-a765-00a0c91e6bf6"
		srvErr := make(chan error, 1)
		srvData := make(chan []byte, 1)
		go func() {
			qs := newSocket(qsocket.Server, secret)
			if err := qs.Dial(useTLS); err != nil {
				srvErr <- err
				return
			}
			defer qs.Close()
			buf := make([]byte, 5)
			_, err := io.ReadFull(qs, buf)
			srvData <- buf
			srvErr <- err
			qs.Write([]byte("world"))
		}()

		// Give the server peer time to knock first, as a listener would.
		time.Sleep(50 * time.Millisecond)
		qs := newSocket(qsocket.Client, secret)
		dialed := make(chan error, 1)
		go func() { dialed <- qs.Dial(useTLS) }()
		select {
		case err := <-dialed:
			if err != nil {
				t.Fatalf("session %d: client dial: %v", i, err)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("session %d: handshake hung, the first SRP message was lost", i)
		}
		if !qs.IsE2E() {
			t.Fatalf("session %d: E2E not active", i)
		}
		qs.Write([]byte("hello"))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(qs, buf); err != nil {
			t.Fatalf("session %d: client read: %v", i, err)
		}
		qs.Close()
		if err := <-srvErr; err != nil {
			t.Fatalf("session %d: server: %v", i, err)
		}
		if got := <-srvData; !bytes.Equal(got, []byte("hello")) || string(buf) != "world" {
			t.Fatalf("session %d: got %q / %q", i, got, buf)
		}
	}
}

func TestTorKnockHost(t *testing.T) {
	ln := listen(t)
	useGate(t, ln)
	reqCh := serveOnce(t, ln, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
	// TOR_MODE without a proxy still dials QSRN_GATE (the loopback gate),
	// but the knock must name the onion gate it stands for.
	qsocket.TOR_MODE = true
	saved := qsocket.QSRN_TOR_GATE
	defer func() { qsocket.QSRN_TOR_GATE = saved }()
	qsocket.QSRN_TOR_GATE = "example.onion"

	qs := qsocket.NewSocket(qsocket.Client, "example-secret")
	qs.SetE2E(false)
	if err := qs.Dial(false); err != nil {
		t.Fatalf("dial: %v", err)
	}
	qs.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if h := headerValue(<-reqCh, "Host"); h != "example.onion:"+port {
		t.Fatalf("Host = %q, want the onion gate", h)
	}
}

func TestKnockCarriesUID(t *testing.T) {
	secret := "example-secret"
	base := md5.Sum([]byte(secret))
	next := qsocket.NextUID(base)
	if want := md5.Sum(base[:]); next != want {
		t.Fatalf("NextUID = %x, want md5(uid) %x", next, want)
	}

	for _, tc := range []struct {
		name string
		set  bool
		want [16]byte
	}{
		{"default md5(secret)", false, base},
		{"chained md5(uid)", true, next},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := listen(t)
			useGate(t, ln)
			reqCh := serveOnce(t, ln, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
			qs := qsocket.NewSocket(qsocket.Server, secret)
			qs.SetE2E(false)
			if tc.set {
				if err := qs.SetUID(next); err != nil {
					t.Fatal(err)
				}
			}
			if qs.UID() != tc.want {
				t.Fatalf("UID() = %x, want %x", qs.UID(), tc.want)
			}
			if err := qs.Dial(false); !errors.Is(err, qsocket.ErrPeerNotFound) {
				t.Fatalf("unexpected error: %v", err)
			}
			key := headerValue(<-reqCh, "Sec-WebSocket-Key")
			if want := base64.StdEncoding.EncodeToString(tc.want[:]); key != want {
				t.Fatalf("knock key = %q, want %q", key, want)
			}
		})
	}
}
