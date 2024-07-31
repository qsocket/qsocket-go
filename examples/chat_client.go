package main

import (
	"fmt"
	"os"
	"os/user"

	"github.com/qsocket/qsocket-go"
)

func main() {
	qsock := qsocket.NewSocket(qsocket.Client, "SimpleChatExample!!")

	fmt.Println("[*] Dialing QSRN...")
	// qsock.SetProxy("127.0.0.1:9050") // Dial over socks proxy
	// qsock.SetE2E(false) // Disable E2E encryption
	err := qsock.Dial(true) // Dial QSocket relay (TLS+E2E enabled)
	if err != nil {
		fmt.Printf("[-] Dial failed: %s\n", err)
		os.Exit(1)
	}
	defer qsock.Close()
	fmt.Println("[+] Connected!")
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}

	fmt.Printf("[*] Sending username=%s\n", usr.Username)
	qsock.Write([]byte(usr.Username))
	fmt.Println("[+] Done!")
}
