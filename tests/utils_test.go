package main

import (
	"testing"

	"github.com/qsocket/qsocket-go"
)

func TestNewChecksumUri(t *testing.T) {
	cliUri := qsocket.NewChecksumUri(qsocket.Client)
	srvUri := qsocket.NewChecksumUri(qsocket.Server)
	t.Logf("-> Server: %s\n", srvUri)
	t.Logf("-> Client: %s\n", cliUri)

	if qsocket.CalcChecksum(
		[]byte(cliUri),
		qsocket.CHECKSUM_BASE,
	) != byte(qsocket.Client) {
		t.Errorf("qsocket.Client != %s", cliUri)
	}

	if qsocket.CalcChecksum(
		[]byte(srvUri),
		qsocket.CHECKSUM_BASE,
	) != byte(qsocket.Server) {
		t.Errorf("qsocket.Server != %s", srvUri)
	}

}

func TestGetDeviceUserAgent(t *testing.T) {
	t.Logf("User-Agent: %s\n", qsocket.GetDeviceUserAgent())
}
