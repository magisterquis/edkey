package edkey

/*
 * edkey_test.go
 * Tests for edkey.go
 * By J. Stuart McMurray
 * Created 20230811
 * Last Modified 20230811
 */

import (
	"crypto/ed25519"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Attributes of the smoketest (all-zeros) key
const (
	stPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AIgAAAAAAAAAAAAAAAtzc2gtZWQyNTUxOQAAACAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----` + "\n"
	stFP = "SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk"
)

var stEDKey = ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))

const sshKeygen = "ssh-keygen"

func TestMarshal(t *testing.T) {
	t.Run("smoketest", func(t *testing.T) {
		t.Parallel()
		m, err := marshal(0, stEDKey, "")
		if nil != err {
			t.Fatalf("marshal: %s", err)
			return
		}

		if stPEM != string(m) {
			t.Fatalf(
				"Incorrect generated key\ngot:\n%s\nwant:\n%s",
				m,
				stPEM,
			)
		}

		s, err := ssh.ParsePrivateKey(m)
		if nil != err {
			t.Fatalf("ssh.ParsePrivateKey: %s", err)
		}

		fp := ssh.FingerprintSHA256(s.PublicKey())
		if stFP != fp {
			t.Fatalf(
				"ssh.FingerprintSHA256:\n"+
					" got: %s\n"+
					"want: %s\n",
				fp,
				stFP,
			)
		}
	})

	for i := 0; i < 100; i++ {
		t.Run("randomcheckint", func(t *testing.T) {
			t.Parallel()
			ci := rand.Uint32()
			m, err := marshal(ci, stEDKey, "")
			if nil != err {
				t.Fatalf(
					"marshal\n"+
						" ci: %d"+
						"err: %s",
					ci,
					err,
				)
			}
			s, err := ssh.ParsePrivateKey(m)
			if nil != err {
				t.Fatalf("ssh.ParsePrivateKey: %s", err)
			}

			fp := ssh.FingerprintSHA256(s.PublicKey())
			if stFP != fp {
				t.Fatalf(
					"ssh.FingerprintSHA256:\n"+
						" got: %s\n"+
						"want: %s\n",
					fp,
					stFP,
				)
			}
		})
	}

	for i := 0; i < 100; i++ {
		var seenFPs sync.Map
		t.Run("randomkey", func(t *testing.T) {
			t.Parallel()
			_, kr, err := ed25519.GenerateKey(nil)
			if nil != err {
				t.Fatalf("ed25519.GenerateKey: %s", err)
			}
			m, err := ToPEM(kr, time.Now().Format(time.RFC3339))
			if nil != err {
				t.Fatalf("ToPEM: %s", err)
			}
			s, err := ssh.ParsePrivateKey(m)
			if nil != err {
				t.Fatalf("ssh.ParsePrivateKey: %s", err)
			}
			fp := ssh.FingerprintSHA256(s.PublicKey())
			if stFP == fp {
				t.Fatalf("got smoketest fingerprint")
			}
			v, ok := seenFPs.LoadOrStore(fp, kr)
			skr := v.(ed25519.PrivateKey)
			if !ok { /* Good. */
				return
			}
			if !skr.Equal(kr) { /* Collision. */
				t.Fatalf(
					"Fingerprint collision:\n%02x\n%02x",
					kr,
					skr,
				)
			}
		})
	}
}

func TestMarshalSSHKeygen(t *testing.T) {
	/* These tests require having ssh-keygen around. */
	if _, err := exec.LookPath(sshKeygen); nil != err {
		t.Skipf("Error searching for %s: %s", sshKeygen, err)
	}

	t.Run("comment", func(t *testing.T) {
		t.Parallel()
		c := time.Now().Format(time.RFC3339)
		k, err := marshal(0, stEDKey, c)
		if nil != err {
			t.Fatalf("generate: %s", err)
		}
		got := string(runSSHKeygen(t, "-lf", writeKey(t, k)))
		want := "256 " + stFP + " " + c + " (ED25519)\n"
		if got != want {
			t.Fatalf(
				"Incorrect comment\n"+
					" got: %q\n"+
					"want: %q\n",
				got,
				want,
			)
		}
	})
	t.Run("fingerprint", func(t *testing.T) {
		t.Parallel()
		_, kr, err := ed25519.GenerateKey(nil)
		if nil != err {
			t.Fatalf("ed25519.GenerateKey: %s", err)
		}
		m, err := ToPEM(kr, "")
		if nil != err {
			t.Fatalf("ToPEM: %s", err)
		}
		s, err := ssh.ParsePrivateKey(m)
		if nil != err {
			t.Fatalf("ssh.ParsePrivateKey: %s", err)
		}
		want := "256 " +
			ssh.FingerprintSHA256(s.PublicKey()) +
			"  (ED25519)\n"
		got := string(runSSHKeygen(t, "-lf", writeKey(t, m)))
		if want != got {
			t.Fatalf(
				"Incorrect fingerprint\n"+
					" got: %s\n"+
					"want: %s\n",
				got,
				want,
			)
		}
	})
}

// writeKey writes the key to a file in t.TempDir.  It calls t.Fatal on error.
// The key's file's name is returned.
func writeKey(t *testing.T, k []byte) string {
	f, err := os.CreateTemp(t.TempDir(), "id_ed25519")
	if nil != err {
		t.Fatalf("Error creating temporary file: %s", err)
	}
	defer f.Close()
	if _, err := f.Write(k); nil != err {
		t.Fatalf("Error writing key to %s: %s", f.Name(), err)
	}
	return f.Name()
}

// runSSHKeygen runs ssh-keygen with the given arguments, which should not
// start with "ssh-keygen".  It calls t.Fatalf on error.  ssh-keygen's output
// (including stderr) is returned.
func runSSHKeygen(t *testing.T, args ...string) []byte {
	args = append([]string{sshKeygen}, args...)
	cmd := exec.Command(args[0], args[1:]...)
	o, err := cmd.CombinedOutput()
	if nil != err {
		if 0 == len(o) {
			o = []byte("none")
		}
		t.Fatalf(
			"Running %s\n"+
				"S: %s\n"+
				"   Err: %s\n"+
				"Output: %s",
			args,
			cmd,
			err,
			o,
		)
	}
	return o
}
