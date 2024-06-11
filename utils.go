package qsocket

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
)

const UserAgentTemplate = "Mozilla/5.0 (%s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.3"

func GetDeviceUserAgent() string {
	return fmt.Sprintf(
		UserAgentTemplate,
		strings.ToUpper(runtime.GOOS),
		strings.ToUpper(runtime.GOARCH),
	)
}

func RandomString(charset string, length int) string {
	str := ""
	for i := 0; i < length; i++ {
		str += string(charset[rand.Intn(len(charset))])
	}
	return str
}

func NewChecksumUri(checksum byte) string {
	uri := RandomString(URI_CHARSET, rand.Intn(3)+1)
	for i := 0; i < 16; i++ {
		if CalcChecksum([]byte(uri), CHECKSUM_BASE) == checksum {
			return uri
		}
		uri += RandomString(URI_CHARSET, 1)
	}
	return NewChecksumUri(checksum)
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
