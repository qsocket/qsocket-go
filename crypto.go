package qsocket

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"

	estream "github.com/qsocket/encrypted-stream"
	"github.com/qsocket/go-srp"
)

// InitE2ECipher initiates the end-to-end encrypted stream with the given key.
func (qs *QSocket) InitE2ECipher(key []byte) error {
	if qs.tlsConn == nil { // We need a valid TLS connection for initiating PAKE for E2E.
		return ErrNoTlsConnection
	}

	cipher, err := estream.NewAESGCMCipher(key)
	if err != nil {
		return err
	}

	config := &estream.Config{
		Cipher:                   cipher,
		DisableNonceVerification: true, // This is nessesary because we don't really know who (client/server) speaks first on the relay connection.
	}

	// Create an encrypted stream from a conn.
	encryptedConn, err := estream.NewEncryptedStream(qs.tlsConn, config)
	if err != nil {
		return err
	}
	qs.encConn = encryptedConn
	return nil
}

// InitClientSRP performs the client SRP sequence for establishing PAKE.
func (qs *QSocket) InitClientSRP() ([]byte, error) {
	if qs.IsClosed() {
		return nil, ErrSocketNotConnected
	}

	s, err := srp.New(SRP_BITS)
	if err != nil {
		return nil, err
	}

	srpUser := md5.Sum([]byte(qs.Secret))
	srpPass := sha256.Sum256([]byte(qs.Secret))
	c, err := s.NewClient(srpUser[:], srpPass[:])
	if err != nil {
		return nil, err
	}

	// client credentials (public key and identity) to send to server
	creds := c.Credentials()

	// Send the creds ro server
	_, err = qs.Write([]byte(creds))
	if err != nil {
		return nil, err
	}

	// Receive the server credentials into 'server_creds'; this is the server
	// public key and random salt generated when the verifier was created.
	buf := make([]byte, 4096)
	n, err := qs.Read(buf)
	if err != nil {
		return nil, err
	}
	serverCreds := buf[:n]

	// Now, generate a mutual authenticator to be sent to the server
	auth, err := c.Generate(string(serverCreds))
	if err != nil {
		return nil, err
	}

	// Send the mutual authenticator to the server
	_, err = qs.Write([]byte(auth))
	if err != nil {
		return nil, err
	}

	// 4. receive "proof" that the server too computed the same result.
	n, err = qs.Read(buf)
	if err != nil {
		return nil, err
	}
	proof := buf[:n]

	// Verify that the server actually did what it claims
	if !c.ServerOk(string(proof)) {
		return nil, ErrSrpFailed
	}

	return c.RawKey(), nil
}

// InitServerSRP performs the server SRP sequence for establishing PAKE.
func (qs *QSocket) InitServerSRP() ([]byte, error) {
	if qs.IsClosed() {
		return nil, ErrSocketNotConnected
	}

	srpUser := md5.Sum([]byte(qs.Secret))
	srpPass := sha256.Sum256([]byte(qs.Secret))
	s, err := srp.New(SRP_BITS)
	if err != nil {
		return nil, err
	}

	v, err := s.Verifier(srpUser[:], srpPass[:])
	if err != nil {
		return nil, err
	}

	ih, vh := v.Encode()

	// =====================================================================

	buf := make([]byte, 4096)
	n, err := qs.Read(buf)
	if err != nil {
		return nil, err
	}
	clientCreds := buf[:n]

	// Parse the user info and authenticator from the 'creds' string
	id, A, err := srp.ServerBegin(string(clientCreds))
	if err != nil {
		return nil, err
	}

	if id != ih {
		fmt.Printf("\n--> %s != %s\n", id, ih)
		return nil, ErrSrpFailed
	}

	// Create an SRP instance and Verifier instance from the stored data.
	s, v, err = srp.MakeSRPVerifier(vh)
	if err != nil {
		return nil, err
	}

	// Begin a new client-server SRP session using the verifier and received
	// public key.
	srv, err := s.NewServer(v, A)
	if err != nil {
		return nil, err
	}

	// Generate server credentials to send to the user
	s_creds := srv.Credentials()

	// 1. send 's_creds' to the client
	_, err = qs.Write([]byte(s_creds))
	if err != nil {
		return nil, err
	}

	// 2. receive 'm_auth' from the client
	n, err = qs.Read(buf)
	if err != nil {
		return nil, err
	}
	m_auth := buf[:n]

	// Authenticate user and generate mutual proof of authentication
	proof, ok := srv.ClientOk(string(m_auth))
	if !ok {
		return nil, ErrSrpFailed
	}

	// 3. Send proof to client
	_, err = qs.Write([]byte(proof))
	if err != nil {
		return nil, err
	}

	// Auth succeeded, derive session key
	return srv.RawKey(), nil
}
