package main

import (
	"testing"

	"github.com/qsocket/qsocket-go"
)

func TestNewChecksumUri(t *testing.T) {
	t.Logf("-> Server: %s\n", qsocket.NewChecksumUri(qsocket.PEER_SRV))
	t.Logf("-> Client: %s\n", qsocket.NewChecksumUri(qsocket.PEER_CLI))
}

func TestGetDeviceUserAgent(t *testing.T) {
	t.Logf("User-Agent: %s\n", qsocket.GetDeviceUserAgent())
}
