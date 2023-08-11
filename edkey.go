// Package edkey converts ed25519 private keys to OpenSSH PEM format.
package edkey

/*
 * edkey.go
 * Turn an ed25519 key into an OpenSSH private key
 * Modified By J. Stuart McMurray
 * Created 20170222 by github.com/mikesmitty
 * Last Modified 20230811
 */

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"math/rand"

	"golang.org/x/crypto/ssh"
)

const (
	blockSize    = 8
	cipherName   = "none"
	kdfName      = "none"
	pubkeyPrefix = "\x00\x00\x00\x0b" +
		ssh.KeyAlgoED25519 +
		"\x00\x00\x00 "
)

/* Most of the below code is forked from https://github.com/mikesmitty/edkey */

// ToPEM encodes a ed25519 private key into the OpenSSH PEM private key format,
// optionally setting a comment (ssh-keygen -C -style).  The returned slice is
// suitable to be written to a file and passed to OpenSSH via
// -i/-oIdentityFile.
func ToPEM(key ed25519.PrivateKey, comment string) ([]byte, error) {
	return marshal(rand.Uint32(), key, comment) /* Random since go 1.20 */
}

// marshal is like ToPem, but requires the random checkint be passed in.  This
// is used for testing.
func marshal(
	ci uint32,
	key ed25519.PrivateKey,
	comment string,
) ([]byte, error) {
	// Add our key header (followed by a null byte)
	magic := append([]byte("openssh-key-v1"), 0)

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

	// Fill out the private key fields
	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
		Pad     []byte `ssh:"rest"`
	}{}

	// Set our check ints
	pk1.Check1 = ci
	pk1.Check2 = ci

	// Set our key type
	pk1.Keytype = ssh.KeyAlgoED25519

	// Add the pubkey to the optionally-encrypted block
	ku, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		/* This is silly. */
		return nil, fmt.Errorf(
			"unexpected public key type %T",
			key.Public(),
		)
	}
	pk1.Pub = ku

	// Add our private key
	pk1.Priv = []byte(key)

	// Might be useful to put something in here at some point
	pk1.Comment = comment

	// Add some padding to match the encryption block size within
	// PrivKeyBlock (without Pad field) 8 doesn't match the documentation,
	// but that's what ssh-keygen uses for unencrypted keys. *shrug*
	blockLen := len(ssh.Marshal(pk1))
	padLen := (blockSize - (blockLen % blockSize)) % blockSize
	pk1.Pad = make([]byte, padLen)

	// Padding is a sequence of bytes like: 1, 2, 3...
	for i := 0; i < padLen; i++ {
		pk1.Pad[i] = byte(i + 1)
	}

	// Only going to support unencrypted keys for now
	w.CipherName = cipherName
	w.KdfName = kdfName
	w.KdfOpts = ""
	w.NumKeys = 1
	w.PubKey = append([]byte(pubkeyPrefix), pk1.Pub...)
	w.PrivKeyBlock = ssh.Marshal(pk1)

	magic = append(magic, ssh.Marshal(w)...)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: magic,
	}), nil
}
