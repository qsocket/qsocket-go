package qsocket

import (
	"fmt"
	"math/rand"
	"runtime"
)

var (
	TOP_UA_DEVICES = []string{
		"Macintosh; Intel Mac OS X 10_15_7",
		"Windows NT 10.0; Win64; x64",
		"X11; Linux x86_64",
	}
	BASE_CHROME_VERSION = 110
	BASE_WEBKIT_VERSION = 522
	DeviceOsMap         map[string]int
	DeviceArchMap       map[string]int
)

func init() {
	DeviceOsMap = make(map[string]int)
	DeviceArchMap = make(map[string]int)

	// Go target OS
	// go tool dist list | cut -d '/' -f1|sort -u
	DeviceOsMap["aix"] = 1
	DeviceOsMap["android"] = 2
	DeviceOsMap["dragonfly"] = 4
	DeviceOsMap["freebsd"] = 5
	DeviceOsMap["illumos"] = 6
	DeviceOsMap["ios"] = 7
	DeviceOsMap["js"] = 8
	DeviceOsMap["linux"] = 9
	DeviceOsMap["netbsd"] = 10
	DeviceOsMap["openbsd"] = 11
	DeviceOsMap["plan9"] = 12
	DeviceOsMap["solaris"] = 13
	DeviceOsMap["wasip1"] = 14
	DeviceOsMap["windows"] = 15

	// Go target architectures
	// go tool dist list | cut -d '/' -f2|sort -u
	DeviceArchMap["386"] = 1
	DeviceArchMap["amd64"] = 2
	DeviceArchMap["arm"] = 3
	DeviceArchMap["arm64"] = 4
	DeviceArchMap["loong64"] = 5
	DeviceArchMap["mips"] = 6
	DeviceArchMap["mips64"] = 7
	DeviceArchMap["mips64le"] = 8
	DeviceArchMap["mipsle"] = 9
	DeviceArchMap["ppc64"] = 10
	DeviceArchMap["ppc64le"] = 11
	DeviceArchMap["riscv64"] = 12
	DeviceArchMap["s390x"] = 13
	DeviceArchMap["wasm"] = 14

}

func GetDeviceUserAgent() string {
	randFloat := rand.Intn(100) + 10
	chrome := DeviceOsMap[runtime.GOOS] + BASE_CHROME_VERSION
	webkit := DeviceArchMap[runtime.GOARCH] + BASE_WEBKIT_VERSION
	randDevice := TOP_UA_DEVICES[rand.Intn(len(TOP_UA_DEVICES))]

	return fmt.Sprintf(
		"Mozilla/5.0 (%s) AppleWebKit/%d.%d (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/%d.%d",
		randDevice,
		webkit,
		randFloat,
		chrome,
		webkit,
		randFloat,
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
