package edkey

/*
 * example_test.go
 * Document us a bit better
 * By J. Stuart McMurray
 * Created 20230811
 * Last Modified 20230811
 */

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"math/rand"

	"golang.org/x/crypto/ssh"
)

func Example() {
	/* Predictable random source.  Please don't do this in real code. */
	rs := rand.New(rand.NewSource(0))

	/* Generate an ED25519 key and PEMify it. */
	_, kr, err := ed25519.GenerateKey(rs)
	if nil != err {
		log.Fatalf("Error generating key: %s", err)
	}
	spem, err := ToPEM(kr, "A fancy example key")
	if nil != err {
		log.Fatalf("Error converting to OpenSSH PEM format: %s", err)
	}
	/* spem can now be written to disk and passed to ssh -i. */

	/* We can also use it with x/crypto/ssh. */
	s, err := ssh.ParsePrivateKey(spem)
	if nil != err {
		log.Fatalf("Parsing PEM: %s", err)
	}
	fmt.Printf(
		"Fingerprint: %s\n",
		ssh.FingerprintSHA256(s.PublicKey()),
	)
	// Output:
	// Fingerprint: SHA256:Wa1InoB8MuILNZy9CjDRvHn9c6afuXSwS7Vm+/addOA
}
