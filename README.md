# QSocket Go
Go library for qsocket...


###### Documentation 
[![GoDoc](https://godoc.org/github.com/qsocket/qsocket-go?status.svg)](http://godoc.org/github.com/qsocket/qsocket-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/qsocket/qs-netcat)](https://goreportcard.com/report/github.com/qsocket/qs-netcat)
[![License: MIT](https://img.shields.io/github/license/qsocket/qsocket-go.svg)](https://raw.githubusercontent.com/qsocket/qsocket-go/master/LICENSE)

## Example
Usage is really simple, `qsocket.New()` function simply creates a new quantum socket with given secret, it includes all the functions of standard `net` sockets and also implements `io Read/Write`. After creating a socket you need to dial the QSRN network by calling `Dial*` functions. Simple example below...
```go
    qsock := qsocket.New("my-secret");  // Create a new QSocket with TLS fingerprint checking...
    qsock.Dial(true)  // Dial using TLS and certificate fingerprint checking...
    // OR
    qsock.Dial(false) // Dial using TCP... 

    // Dial using a socks5 proxy
    qsock.SetProxy("127.0.0.1:9050")
    qsock.Dial()

``` 

After dialing the QSRN, socket is ready for read/write operations.
