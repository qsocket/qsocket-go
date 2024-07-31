package qsocket

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Some global constants for
// These values can be changed for obfuscating the knock protocol
const (
	// QSRN_GATE is the static gate address for the QSocket network.
	QSRN_GATE = "relay.qsocket.io"
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
)

var (
	ErrFailedReadingProtocolSwitchResponse = errors.New("Failed reading protocol switch response.")
	ErrInvalidProtocolSwitchResponse       = errors.New("Invalid protocol switch response.")
	ErrProtocolSwitchFailed                = errors.New("Websocket protocol switch failed.")
	ErrServerCollision                     = errors.New("Address already in use. (server secret collision)")
	ErrPeerNotFound                        = errors.New("Connection refused. (no server listening with given secret)")
	ErrUpgradeRequired                     = errors.New("Protocol upgrade required!")

	HttpResponseRgx    = regexp.MustCompile(`^HTTP/([0-9]|[0-9]\.[0-9]) ([0-9]{1,3}) [a-z A-Z]+`)
	WebsocketAcceptRgx = regexp.MustCompile(`Sec-WebSocket-Accept: ([A-Za-z0-9+/]+={0,2})`)
)

// GET /[RANDOM-URI] HTTP/1.1
// Sec-WebSocket-Version: 13
// Sec-WebSocket-Key: fTZr3JpRgUwbDNAMdJvyRg==  <-- base64 encoded UID here
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/524.81 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/524.81
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
	req += "Upgrade: websocket"
	req += (CRLF + CRLF)

	n, err := qs.Write([]byte(req))
	if err != nil {
		return err
	}
	if n != len(req) {
		return ErrProtocolSwitchFailed
	}

	buf := make([]byte, 4096)
	n, err = qs.Read(buf)
	if err != nil {
		return err
	}

	if !HttpResponseRgx.Match(buf[:n]) {
		return ErrInvalidProtocolSwitchResponse
	}

	resp := HttpResponseRgx.FindStringSubmatch(string(buf[:n]))
	if len(resp) != 3 {
		return ErrInvalidProtocolSwitchResponse
	}

	switch resp[2] { // Status code
	case "101":
		return nil
	case "404":
		return ErrPeerNotFound
	case "409":
		return ErrServerCollision
	case "426":
		relayMessage := strings.Split(string(buf[:n]), "\n\n")
		if len(relayMessage) > 1 {
			return fmt.Errorf("%s", relayMessage[1])
		}
		return ErrUpgradeRequired
	default:
		return ErrInvalidProtocolSwitchResponse
	}
}

func (qs *QSocket) InitiateKnockSequence() error {
	if qs.IsClosed() {
		return ErrSocketNotConnected
	}

	err := qs.DoWsProtocolSwitch()
	if err != nil {
		return err
	}

	if qs.e2e {
		sessionKey := []byte{}
		if qs.IsClient() {
			sessionKey, err = qs.InitClientSRP()
		} else {
			sessionKey, err = qs.InitServerSRP()
		}
		if err != nil {
			return err
		}

		err = qs.InitE2ECipher(sessionKey)
		if err != nil {
			return err
		}
	}
	return nil
}
