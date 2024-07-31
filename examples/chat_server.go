package main

import (
	"fmt"

	"github.com/qsocket/qsocket-go"
)

func main() {
	qsock := qsocket.NewSocket(qsocket.Server, "SimpleChatExample!!")

	fmt.Println("[*] Dialing QSRN...")
	// qsock.SetProxy("127.0.0.1:9050") // Dial over socks proxy
	// qsock.SetE2E(false) // Disable E2E encryption
	err := qsock.Dial(true) // Dial QSocket relay (TLS+E2E enabled)
	if err != nil {
		fmt.Printf("[-] Dial failed: %s\n", err)
	}
	fmt.Println("[+] Connected!")
	fmt.Println("[*] Reading...")
	buf := make([]byte, 1024)
	n, err := qsock.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[+] Read: %s\n", string(buf[:n]))

}
