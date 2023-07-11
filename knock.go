package qsocket

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Some global constants for
// These values can be changed for obfuscating the knock protocol
const (
	// QSRN_GATE is the static gate address for the QSocket network.
	QSRN_GATE = "gate.qsocket.io"
	// QSRN_GATE_TLS_PORT Default TLS port for the QSocket gate.
	QSRN_GATE_TLS_PORT = 443
	// QSRN_GATE_PORT Default TCP port for the QSocket gate.
	QSRN_GATE_PORT = 80
	// CERT_FINGERPRINT is the static TLS certificate fingerprint for QSRN_GATE.
	CERT_FINGERPRINT = "32ADEB12BA582C97E157D10699080C1598ECC3793C09D19020EDF51CDC67C145"

	// KNOCK_CHECKSUM_BASE is the constant base value for calculating knock packet checksums.
	KNOCK_CHECKSUM_BASE = 0xEE
	CRLF                = "\r\n"
)

const (
	// ================ KNOCK RESPONSE CODES ================
	// KNOCK_SUCCESS is the knock sequence response code indicating successful connection.
	KNOCK_SUCCESS = iota // Protocol switch
	// KNOCK_FAIL is the knock sequence response code indicating failed connection.
	KNOCK_FAIL // Unauthorized
	// KNOCK_BUSY is the knock sequence response code indicating busy connection.
	KNOCK_BUSY
	// KNOCK_IN_USE is the knock sequence response code indicating busy connection.
	KNOCK_IN_USE
)

var (
	ErrFailedReadingKnockResponse = errors.New("failed reading knock response")
	ErrInvalidKnockResponse       = errors.New("invalid knock response")
	ErrKnockSendFailed            = errors.New("knock sequence send failed")
	ErrConnRefused                = errors.New("connection refused (no server listening with given secret)")
	ErrSocketBusy                 = errors.New("socket busy")

	HttpResponseRgx    = regexp.MustCompile(`^HTTP/([0-9]|[0-9]\.[0-9]) ([0-9]{1,3}) [a-z A-Z]+`)
	WebsocketAcceptRgx = regexp.MustCompile(`Sec-WebSocket-Accept: ([A-Za-z0-9+/]+={0,2})`)
)

type KnockResponse struct {
	Success bool
	Forward bool
	Data    []byte
}

// Knock packet is stored inside the "Sec-WebSocket-Key" header of the initial protocol switch request

// GET / HTTP/1.1
// Sec-WebSocket-Version: 13
// Sec-WebSocket-Key: fTZr3JpRgUwbDNAMdJvyRg==  <-- base64 encoded knock here
// Connection: Upgrade
// Upgrade: websocket
// Host: dev.qsocket.io

// Knock packet is 20 bytes in size
// and contains the checksum (1 byte), UUID (16 byte), architecture (1 byte), operating system 1 (byte), peer mode (1 byte)
// [(CHECKSUM)|(UUID)|(ARCH)|(OS)|(PEER)]

// SendKnockSequence sends a knock sequence to the QSRN gate
// with the socket properties.
func (qs *QSocket) SendKnockSequence() (*KnockResponse, error) {
	knock, err := qs.NewKnockSequence()
	if err != nil {
		return nil, err
	}

	req := fmt.Sprintf("GET /%s HTTP/1.1\n", qs.forward)
	req += fmt.Sprintf("Host: %s\n", QSRN_GATE)
	req += "Sec-WebSocket-Version: 13\n"
	req += fmt.Sprintf(
		"Sec-WebSocket-Key: %s\n",
		base64.StdEncoding.EncodeToString(knock),
	)
	req += "Connection: Upgrade\n"
	req += "Upgrade: websocket\n"
	req += (CRLF + CRLF)

	n, err := qs.Write([]byte(req))
	if err != nil {
		return nil, err
	}
	if n != len(req) {
		return nil, ErrKnockSendFailed
	}

	buf := make([]byte, 256)
	_, err = qs.Read(buf)
	if err != nil {
		return nil, err
	}

	return ParseKnockResponse(buf)
}

func ParseKnockResponse(buf []byte) (*KnockResponse, error) {
	if !strings.Contains(string(buf), CRLF+CRLF) {
		return nil, ErrFailedReadingKnockResponse
	}

	knockResp := new(KnockResponse)
	if !HttpResponseRgx.Match(buf) {
		return nil, ErrInvalidKnockResponse
	}

	resp := HttpResponseRgx.FindStringSubmatch(string(buf))
	if len(resp) != 3 {
		return nil, ErrInvalidKnockResponse
	}

	switch resp[2] { // Status code
	case "101":
		knockResp.Success = true
		// Check if there is a "Sec-WebSocket-Accept" header in the response
		respData := WebsocketAcceptRgx.FindStringSubmatch(string(buf))
		if len(respData) == 2 {
			knockResp.Forward = true
			data, err := base64.StdEncoding.DecodeString(respData[1])
			if err != nil {
				return nil, err
			}
			knockResp.Data = data
		}
	case "401":
		knockResp.Success = false
	case "409":
		return nil, ErrAddressInUse
	default:
		return nil, ErrInvalidKnockResponse
	}
	return knockResp, nil
}

// NewKnockSequence generates a new knock packet with given UUID and tag values.
func (qs *QSocket) NewKnockSequence() ([]byte, error) {
	uid := md5.Sum([]byte(qs.secret))
	u, err := uuid.Parse(qs.secret)
	if err == nil {
		uid = u
	}

	knock := append(uid[:], qs.archTag, qs.osTag, qs.peerTag)
	checksum := CalcChecksum(knock, KNOCK_CHECKSUM_BASE)
	return append([]byte{checksum}, knock...), nil
}

// CalcChecksum calculates the modulus based checksum of the given data,
// modulus base is given in the base variable.
func CalcChecksum(data []byte, base byte) byte {
	checksum := uint32(0)
	for _, n := range data {
		checksum += uint32((n << 2) % base)
	}
	return byte(checksum % uint32(base))
}
