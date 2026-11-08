package qsocket

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Some global constants for
// These values can be changed for obfuscating the knock protocol
const (
	// CHECKSUM_BASE is the constant base value for calculating knock sequence URI checksums.
	CHECKSUM_BASE = 0xEE
	URI_CHARSET   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	CRLF          = "\r\n"
	// MAX_RESPONSE_HEADER_LEN is the largest protocol switch response header
	// block accepted from the gate.
	MAX_RESPONSE_HEADER_LEN = 16 * 1024
	// MAX_RESPONSE_BODY_LEN is the largest response body read for showing the
	// message of a refused protocol switch.
	MAX_RESPONSE_BODY_LEN = 4096
)

var (
	ErrFailedReadingProtocolSwitchResponse = errors.New("Failed reading protocol switch response.")
	ErrInvalidProtocolSwitchResponse       = errors.New("Invalid protocol switch response.")
	ErrProtocolSwitchFailed                = errors.New("Websocket protocol switch failed.")
	ErrServerCollision                     = errors.New("Address already in use. (server secret collision)")
	ErrPeerNotFound                        = errors.New("Connection refused. (no server listening with given secret)")
	ErrUpgradeRequired                     = errors.New("Protocol upgrade required!")

	HttpResponseRgx = regexp.MustCompile(`^HTTP/([0-9]|[0-9]\.[0-9]) ([0-9]{1,3}) [a-z A-Z]+`)

	// QSRN_GATE is the static gate address for the QSocket network.
	QSRN_GATE = "relay.qsocket.io"
	// QSRN_TOR_GATE is the static ONION address for the QSocket network.
	QSRN_TOR_GATE = "5cah65fto4tjklhocryenlgti6bfnh4y5szjfvxeqqh3vvw2ff4uq2id.onion"
	// QSRN_GATE_TLS_PORT Default TLS port for the QSocket gate.
	QSRN_GATE_TLS_PORT = 443
	// QSRN_GATE_PORT Default TCP port for the QSocket gate.
	QSRN_GATE_PORT = 80
)

// The knock is a WebSocket upgrade request laid out the way Chrome sends one
// over HTTP/1.1, every header in Chrome's (fixed) order and every line ended
// with CRLF. See KnockRequest.
//
// GET /[RANDOM-URI] HTTP/1.1
// Host: relay.qsocket.io
// Connection: Upgrade
// Pragma: no-cache
// Cache-Control: no-cache
// User-Agent: Mozilla/5.0 (LINUX; AMD64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.1.0 Safari/537.36
// Upgrade: websocket
// Origin: https://relay.qsocket.io
// Sec-WebSocket-Version: 13
// Accept-Encoding: gzip, deflate, br, zstd
// Accept-Language: en-US,en;q=0.9
// Sec-WebSocket-Key: fTZr3JpRgUwbDNAMdJvyRg==  <-- base64 encoded UID here
// Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits

// knockHost returns the gate name carried in the Host and Origin headers,
// the gate actually dialed, with the port only when it is not the default one
// of the transport.
func (qs *QSocket) knockHost() string {
	gate := QSRN_GATE
	if TOR_MODE {
		gate = QSRN_TOR_GATE
	}
	port, defPort := QSRN_GATE_PORT, 80
	if qs.IsTLS() {
		port, defPort = QSRN_GATE_TLS_PORT, 443
	}
	if strings.Contains(gate, ":") && !strings.HasPrefix(gate, "[") {
		gate = "[" + gate + "]" // IPv6 literal
	}
	if port != defPort {
		return fmt.Sprintf("%s:%d", gate, port)
	}
	return gate
}

// knockOrigin returns the Origin header value for the given host.
func (qs *QSocket) knockOrigin(host string) string {
	if qs.IsTLS() {
		return "https://" + host
	}
	return "http://" + host
}

// DoWsProtocolSwitch sends the knock sequence to the QSRN gate and reads its
// response.
//
// The response is read through the buffered reader of the socket up to the
// end of its header block, whatever follows it (the first SRP message of the
// peer, forwarded right after the switch) stays in the buffer for the next
// read.
func (qs *QSocket) DoWsProtocolSwitch() error {
	if qs.IsClosed() || qs.reader == nil {
		return ErrSocketNotConnected
	}

	uid := md5.Sum([]byte(qs.secret))
	host := qs.knockHost()
	req := KnockRequest(
		NewChecksumUri(qs.socketType),
		host,
		qs.knockOrigin(host),
		GetDeviceUserAgent(),
		base64.StdEncoding.EncodeToString(uid[:]),
	)

	n, err := qs.transport.Write([]byte(req))
	if err != nil {
		return err
	}
	if n != len(req) {
		return ErrProtocolSwitchFailed
	}

	status, headers, err := qs.readResponseHeader()
	if err != nil {
		return err
	}

	switch status {
	case "101":
		return nil
	case "404":
		return ErrPeerNotFound
	case "409":
		return ErrServerCollision
	case "426":
		if msg := qs.readResponseBody(headers); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return ErrUpgradeRequired
	default:
		return ErrInvalidProtocolSwitchResponse
	}
}

// readResponseHeader reads the header block of the gate response, lines may
// end with CRLF or a bare LF, the block ends with an empty line. It returns
// the status code and the header lines.
func (qs *QSocket) readResponseHeader() (string, []string, error) {
	var lines []string
	total := 0
	for {
		line, err := qs.reader.ReadString('\n')
		total += len(line)
		if total > MAX_RESPONSE_HEADER_LEN {
			return "", nil, ErrInvalidProtocolSwitchResponse
		}
		if err != nil {
			if len(lines) == 0 && line == "" {
				return "", nil, err
			}
			return "", nil, ErrFailedReadingProtocolSwitchResponse
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return "", nil, ErrInvalidProtocolSwitchResponse
	}

	resp := HttpResponseRgx.FindStringSubmatch(lines[0])
	if len(resp) != 3 {
		return "", nil, ErrInvalidProtocolSwitchResponse
	}
	return resp[2], lines[1:], nil
}

// readResponseBody reads the body of a refusal response, sized by its
// Content-Length header, or whatever is already buffered without one.
func (qs *QSocket) readResponseBody(headers []string) string {
	size := -1
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			if v, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && v >= 0 {
				size = v
			}
		}
	}
	if size < 0 {
		size = qs.reader.Buffered()
	}
	if size > MAX_RESPONSE_BODY_LEN {
		size = MAX_RESPONSE_BODY_LEN
	}
	body := make([]byte, size)
	n, _ := io.ReadFull(qs.reader, body)
	return strings.TrimSpace(string(body[:n]))
}

func (qs *QSocket) InitKnockSequence() error {
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
