package qsocket

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
)

const UserAgentTemplate = "Mozilla/5.0 (%s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.%s Safari/537.36"

func GetDeviceUserAgent() string {
	return fmt.Sprintf(
		UserAgentTemplate,
		strings.ToUpper(runtime.GOOS),
		strings.ToUpper(runtime.GOARCH),
		Version,
	)
}

// KnockRequest builds the WebSocket upgrade request sent to the QSRN gate.
//
// The headers are the ones Chrome sends for a WebSocket over HTTP/1.1, in
// Chrome's order, which is fixed for every connection. Every line ends with
// CRLF. The order is part of the traffic shape, do not sort or shuffle it.
func KnockRequest(path, host, origin, userAgent, key string) string {
	var b strings.Builder
	b.WriteString("GET /" + path + " HTTP/1.1" + CRLF)
	b.WriteString("Host: " + host + CRLF)
	b.WriteString("Connection: Upgrade" + CRLF)
	b.WriteString("Pragma: no-cache" + CRLF)
	b.WriteString("Cache-Control: no-cache" + CRLF)
	b.WriteString("User-Agent: " + userAgent + CRLF)
	b.WriteString("Upgrade: websocket" + CRLF)
	b.WriteString("Origin: " + origin + CRLF)
	b.WriteString("Sec-WebSocket-Version: 13" + CRLF)
	b.WriteString("Accept-Encoding: gzip, deflate, br, zstd" + CRLF)
	b.WriteString("Accept-Language: en-US,en;q=0.9" + CRLF)
	b.WriteString("Sec-WebSocket-Key: " + key + CRLF)
	b.WriteString("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits" + CRLF)
	b.WriteString(CRLF)
	return b.String()
}

func RandomString(charset string, length int) string {
	str := ""
	for i := 0; i < length; i++ {
		str += string(charset[rand.Intn(len(charset))])
	}
	return str
}

func NewChecksumUri(sType SocketType) string {
	uri := RandomString(URI_CHARSET, rand.Intn(3)+1)
	for i := 0; i < 16; i++ {
		if CalcChecksum([]byte(uri), CHECKSUM_BASE) == byte(sType) {
			return uri
		}
		uri += RandomString(URI_CHARSET, 1)
	}
	return NewChecksumUri(sType)
}

// CalcChecksum calculates the modulus based checksum of the given data,
// modulus base is given in the base variable.
func CalcChecksum(data []byte, base byte) byte {
	checksum := uint32(0)
	for _, n := range data {
		checksum += uint32(n)
		checksum = checksum % uint32(base)
	}
	return byte(checksum)
}
