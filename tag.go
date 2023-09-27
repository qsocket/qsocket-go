package qsocket

import "runtime"

const (
	TAG_OS_UNKNOWN = iota
	TAG_OS_LINUX
	TAG_OS_DARWIN
	TAG_OS_WINDOWS
	TAG_OS_ANDROID
	TAG_OS_IOS
	TAG_OS_FREEBSD
	TAG_OS_OPENBSD
	TAG_OS_NETBSD
	TAG_OS_JS
	TAG_OS_SOLARIS
	TAG_OS_DRAGONFLY
	TAG_OS_ILLUMOS
	TAG_OS_AIX
	TAG_OS_ZOS
	TAG_OS_NACL
	TAG_OS_PLAN9
	TAG_OS_HURD
)

const (
	TAG_ARCH_UNKNOWN = iota
	TAG_ARCH_386
	TAG_ARCH_AMD64
	TAG_ARCH_ARM64P32
	TAG_ARCH_ARM
	TAG_ARCH_ARM64
	TAG_ARCH_ARM64BE
	TAG_ARCH_ARMBE
	TAG_ARCH_LOONG64
	TAG_ARCH_MIPS
	TAG_ARCH_MIPS64
	TAG_ARCH_MIPS64LE
	TAG_ARCH_MIPS64P32
	TAG_ARCH_MIPS64P32LE
	TAG_ARCH_MIPSLE
	TAG_ARCH_PPC
	TAG_ARCH_PPC64
	TAG_ARCH_PPC64LE
	TAG_ARCH_RISCV
	TAG_ARCH_RISCV64
	TAG_ARCH_S390
	TAG_ARCH_S390X
	TAG_ARCH_SPARC
	TAG_ARCH_SPARC64
	TAG_ARCH_WASM
)

func GetOsTag() byte {
	switch runtime.GOOS {
	case "linux":
		return TAG_OS_LINUX
	case "windows":
		return TAG_OS_WINDOWS
	case "darwin":
		return TAG_OS_DARWIN
	case "android":
		return TAG_OS_ANDROID
	case "ios":
		return TAG_OS_IOS
	case "freebsd":
		return TAG_OS_FREEBSD
	case "openbsd":
		return TAG_OS_OPENBSD
	case "netbsd":
		return TAG_OS_NETBSD
	case "solaris":
		return TAG_OS_SOLARIS
	case "illumos":
		return TAG_OS_ILLUMOS
	case "dragonfly":
		return TAG_OS_DRAGONFLY
	case "aix":
		return TAG_OS_AIX
	case "plan9":
		return TAG_OS_PLAN9
	case "nacl":
		return TAG_OS_NACL
	case "js":
		return TAG_OS_JS
	case "hurd":
		return TAG_OS_HURD
	case "zos":
		return TAG_OS_HURD
	}
	return TAG_OS_UNKNOWN
}

func GetArchTag() byte {
	switch runtime.GOARCH {
	case "386":
		return TAG_ARCH_386
	case "amd64":
		return TAG_ARCH_AMD64
	case "arm":
		return TAG_ARCH_ARM
	case "armbe":
		return TAG_ARCH_ARMBE
	case "arm64":
		return TAG_ARCH_ARM64
	case "arm64be":
		return TAG_ARCH_ARM64BE
	case "loon64":
		return TAG_ARCH_LOONG64
	case "mips":
		return TAG_ARCH_MIPS
	case "mipsle":
		return TAG_ARCH_MIPSLE
	case "mips64":
		return TAG_ARCH_MIPS64
	case "mips64le":
		return TAG_ARCH_MIPS64LE
	case "mips64p32":
		return TAG_ARCH_MIPS64P32
	case "mips64p32le":
		return TAG_ARCH_MIPS64P32LE
	case "ppc":
		return TAG_ARCH_PPC
	case "ppc64":
		return TAG_ARCH_PPC64
	case "ppc64le":
		return TAG_ARCH_PPC64LE
	case "riscv":
		return TAG_ARCH_RISCV
	case "riscv64":
		return TAG_ARCH_RISCV64
	case "s390":
		return TAG_ARCH_S390
	case "s390x":
		return TAG_ARCH_S390X
	case "sparc":
		return TAG_ARCH_SPARC
	case "sparc64":
		return TAG_ARCH_SPARC64
	case "wasm":
		return TAG_ARCH_WASM
	}
	return TAG_ARCH_UNKNOWN
}
