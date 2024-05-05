package qsocket

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"regexp"
)

// Some global constants for
// These values can be changed for obfuscating the knock protocol
const (
	// QSRN_GATE is the static gate address for the QSocket network.
	QSRN_GATE = "gate.qsocket.io"
	// QSRN_TOR_GATE is the static ONION address for the QSocket network.
	QSRN_TOR_GATE = "5cah65fto4tjklhocryenlgti6bfnh4y5szjfvxeqqh3vvw2ff4uq2id.onion"
	// QSRN_GATE_TLS_PORT Default TLS port for the QSocket gate.
	QSRN_GATE_TLS_PORT = 443
	// QSRN_GATE_PORT Default TCP port for the QSocket gate.
	QSRN_GATE_PORT = 80
	// CHECKSUM_BASE is the constant base value for calculating knock sequence URI checksums.
	CHECKSUM_BASE = 0xEE
	URI_CHARSET   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	CRLF          = "\r\n"

	// ================ KNOCK RESPONSE CODES ================
	// KNOCK_SUCCESS is the knock sequence response code indicating successful connection.
	KNOCK_SUCCESS = iota // Protocol switch
	// KNOCK_FAIL is the knock sequence response code indicating no peer is listening with the given secret.
	KNOCK_FAIL
	// KNOCK_COLLISION is the knock sequence response code indicating another server is already listening with the given secret.
	KNOCK_COLLISION
)

var (
	ErrFailedReadingProtocolSwitchResponse = errors.New("failed reading protocol switch response")
	ErrInvalidProtocolSwitchResponse       = errors.New("invalid protocol switch response")
	ErrProtocolSwitchFailed                = errors.New("websocket protocol switch failed")
	ErrConnRefused                         = errors.New("connection refused (no server listening with given secret)")

	HttpResponseRgx    = regexp.MustCompile(`^HTTP/([0-9]|[0-9]\.[0-9]) ([0-9]{1,3}) [a-z A-Z]+`)
	WebsocketAcceptRgx = regexp.MustCompile(`Sec-WebSocket-Accept: ([A-Za-z0-9+/]+={0,2})`)
)

type SocketSpecs struct {
	Command     string
	ForwardAddr string
	TermSize    ttySize
}

// GET / HTTP/1.1
// Sec-WebSocket-Version: 13
// Sec-WebSocket-Key: fTZr3JpRgUwbDNAMdJvyRg==  <-- base64 encoded UID here
// Connection: Upgrade
// Upgrade: websocket
// Host: dev.qsocket.io

// SendKnockSequence sends a knock sequence to the QSRN gate
// with the socket properties.
func (qs *QSocket) DoWsProtocolSwitch() error {
	if qs.IsClosed() {
		return ErrSocketNotConnected
	}

	uid := md5.Sum([]byte(qs.secret))
	req := fmt.Sprintf("GET /%s HTTP/1.1\n", NewChecksumUri(qs.peerTag))
	req += fmt.Sprintf("Host: %s\n", QSRN_GATE)
	req += fmt.Sprintf("User-Agent: %s\n", GetDeviceUserAgent())
	req += "Sec-WebSocket-Version: 13\n"
	req += fmt.Sprintf(
		"Sec-WebSocket-Key: %s\n",
		base64.StdEncoding.EncodeToString(uid[:]),
	)
	req += "Connection: Upgrade\n"
	req += "Upgrade: websocket\n"
	req += (CRLF)

	n, err := qs.Write([]byte(req))
	if err != nil {
		return err
	}
	if n != len(req) {
		return ErrProtocolSwitchFailed
	}

	buf := make([]byte, 4096)
	_, err = qs.Read(buf)
	if err != nil {
		return err
	}

	if !HttpResponseRgx.Match(buf) {
		return ErrInvalidProtocolSwitchResponse
	}

	resp := HttpResponseRgx.FindStringSubmatch(string(buf))
	if len(resp) != 3 {
		return ErrInvalidProtocolSwitchResponse
	}

	switch resp[2] { // Status code
	case "101":
		return nil
	case "401":
		return ErrConnRefused
	case "409":
		return ErrAddressInUse
	default:
		return ErrInvalidProtocolSwitchResponse
	}
}

func (qs *QSocket) SendSocketSpecs() error {
	if qs.IsClosed() {
		return ErrSocketNotConnected
	}
	specs := SocketSpecs{
		Command:     qs.command,
		ForwardAddr: qs.forward,
		TermSize:    *qs.termSize,
	}
	buf := bytes.Buffer{}
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(specs); err != nil {
		return err
	}

	_, err := qs.Write(buf.Bytes())
	return err
}

func (qs *QSocket) RecvSocketSpecs() (*SocketSpecs, error) {
	if qs.IsClosed() {
		return nil, ErrSocketNotConnected
	}
	specs := new(SocketSpecs)
	data := make([]byte, 512)
	n, err := qs.Read(data)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data[:n])
	dec := gob.NewDecoder(buf)

	if err := dec.Decode(specs); err != nil {
		return nil, err
	}

	return specs, nil
}
