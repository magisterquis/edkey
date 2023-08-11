edkey
=====
edkey formats an
[ED25519 private key](https://pkg.go.dev/crypto/ed25519#PrivateKey)
in OpenSSH's PEM
[format](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=1.3&content-type=text/x-cvsweb-markup).

Please see [example.go](example.go) for an example.

Installation
------------
```sh
go get github.com/magisterquis/edkey@latest
```

Quickstart
----------
```go
_, kr, err := ed25519.GenerateKey(nil)
if nil != err {
        log.Fatalf("Error generating key: %s", err)
}
p, err := edkey.ToPEM(kr, "")
if nil != err {
        log.Fatalf("Error PEMifying key: %s", err)
}
if err := os.WriteFile("id_ed25519", p, 0600); nil != err {
        log.Fatalf("Error writing key to file: %s", err)
}
```

Credit
------
Many thanks to [mikesmitty](https://github.com/mikesmitty) for the
[original version](https://github.com/mikesmitty/edkey) of this library.
