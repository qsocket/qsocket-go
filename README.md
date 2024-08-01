# QSocket Go
Go library for qsocket...


###### Documentation 
[![GoDoc](https://godoc.org/github.com/qsocket/qsocket-go?status.svg)](http://godoc.org/github.com/qsocket/qsocket-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/qsocket/qs-netcat)](https://goreportcard.com/report/github.com/qsocket/qs-netcat)
[![License: MIT](https://img.shields.io/github/license/qsocket/qsocket-go.svg)](https://raw.githubusercontent.com/qsocket/qsocket-go/master/LICENSE)


> [!WARNING]  
> This library is in its early alpha development stage, featuring experimental functionality that may lack backwards compatibility, and users are advised to exercise caution and not use it in production environments.

## Example
Usage is really simple, `qsocket.NewSocket()` function simply creates a new quantum socket with given secret, it includes all the functions of standard `net` sockets and also implements `io Read/Write`. After creating a socket you need to dial the QSRN network by calling `Dial*` functions. Simple example below...
```go
    // Create a new QSocket client...
    qsock := qsocket.NewSocket(qsocket.Client, "my-secret");
    // Create a new QSocket server...
    qsock := qsocket.NewSocket(qsocket.Server, "my-secret");
    
    qsock.Dial(true)  // Dial using TLS...
    // OR
    qsock.Dial(false) // Dial using TCP... 

    // Dial using a socks5 proxy over TLS
    qsock.SetProxy("127.0.0.1:9050")
    qsock.Dial(true)

``` 

After dialing the QSRN, socket is ready for read/write operations. Check [here](https://github.com/qsocket/qsocket-go/tree/dev/examples) and [qs-netcat](https://github.com/qsocket/qs-netcat) for more usage examples. 
