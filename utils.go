package qsocket

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
)

var (
	TOP_UA_DEVICES = []string{
		"Macintosh; Intel Mac OS X 10_15_7",
		"Windows NT 10.0; Win64; x64",
		"X11; Linux x86_64",
	}
	// Go target OS
	// go tool dist list | cut -d '/' -f1|sort -u
	TARGET_OS_LIST = []string{
		"AIX",
		"ANDROID",
		"DARWIN",
		"DRAGONFLY",
		"FREEBSD",
		"ILLUMOS",
		"IOS",
		"JS",
		"LINUX",
		"NETBSD",
		"OPENBSD",
		"PLAN9",
		"SOLARIS",
		"WASIP1",
		"WINDOWS",
	}

	// Go target architectures
	// go tool dist list | cut -d '/' -f2|sort -u
	TARGET_ARCH_LIST = []string{
		"386",
		"AMD64",
		"ARM",
		"ARM64",
		"LOONG64",
		"MIPS",
		"MIPS64",
		"MIPS64LE",
		"MIPSLE",
		"PPC64",
		"PPC64LE",
		"RISCV64",
		"S390X",
		"WASM",
	}

	BASE_CHROME_VERSION = 110
	BASE_WEBKIT_VERSION = 522
	DeviceOsMap         map[string]int
	DeviceArchMap       map[string]int
)

func init() {
	DeviceOsMap = make(map[string]int)
	DeviceArchMap = make(map[string]int)

	for i, v := range TARGET_OS_LIST {
		DeviceOsMap[v] = i
	}

	for i, v := range TARGET_ARCH_LIST {
		DeviceArchMap[v] = i
	}
}

func GetDeviceUserAgent() string {
	randFloat := rand.Intn(100) + 10
	chrome := DeviceArchMap[strings.ToUpper(runtime.GOARCH)] + BASE_CHROME_VERSION
	webkit := DeviceOsMap[strings.ToUpper(runtime.GOOS)] + BASE_WEBKIT_VERSION
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
