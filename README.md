# QSocket Go
Go library for qsocket...


###### Documentation 
[![GoDoc](https://godoc.org/github.com/qsocket/qsocket-go?status.svg)](http://godoc.org/github.com/qsocket/qsocket-go)
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

## Certificate validation

By default the gate certificate is validated against the system roots, like
any TLS client.

`SetCertFingerprint` pins the gate's certificate instead. It takes the hex
encoded SHA-256 hash of the leaf certificate's public key (SubjectPublicKeyInfo,
SPKI). A pin replaces the CA validation, so a gate with a self signed
certificate can be used, while the TLS handshake signature is still checked,
so the gate has to hold the matching private key. The check runs right after
the TLS handshake, before any knock byte is sent, and a mismatch returns
`ErrUntrustedCert`. The hash of a certificate in `cert.pem` is computed with:

```bash
openssl x509 -pubkey -noout -in cert.pem | openssl pkey -pubin -outform der | openssl dgst -sha256
```

`SetInsecureCert(true)` turns the validation off when no fingerprint is
pinned, any certificate is accepted and the identity of the gate is not
checked. It is meant for testing, a pinned fingerprint takes precedence over
it.

```go
    qsock := qsocket.NewSocket(qsocket.Client, "my-secret")
    qsock.SetCertFingerprint("<64 hex characters>") // pin the gate key
    qsock.Dial(true)
```

`VerifyTlsCertificate` is removed, the check is part of the TLS handshake
now.

> [!NOTE]
> The public gate `relay.qsocket.io` is served through Cloudflare, whose edge
> certificates and keys rotate often, so a pin of the public gate stops
> working without notice. Pinning is meant for private gates whose key you
> control.
