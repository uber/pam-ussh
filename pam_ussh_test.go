/*
Copyright (c) 2017 Uber Technologies, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestLoadPrincipals(t *testing.T) {
	WithTempDir(func(dir string) {
		p := path.Join(dir, "principals")
		e := ioutil.WriteFile(p, []byte("group:t"), 0444)
		require.NoError(t, e)

		r, e := loadValidPrincipals(p)
		require.NoError(t, e)
		_, ok := r["group:t"]
		require.True(t, ok)
	})
}

func TestNoAuthSock(t *testing.T) {
	oldAgent := os.Getenv("SSH_AUTH_SOCK")
	defer os.Setenv("SSH_AUTH_SOCK", oldAgent)
	os.Unsetenv("SSH_AUTH_SOCK")
	b := new(bytes.Buffer)
	require.Equal(t, AuthError, authenticate(b, 0, "r", "", nil))
	require.Contains(t, b.String(), "No SSH_AUTH_SOCK")
}

func TestBadAuthSock(t *testing.T) {
	WithTempDir(func(dir string) {
		s := path.Join(dir, "badsock")

		oldAgent := os.Getenv("SSH_AUTH_SOCK")
		defer os.Setenv("SSH_AUTH_SOCK", oldAgent)
		os.Setenv("SSH_AUTH_SOCK", s)
		b := new(bytes.Buffer)
		require.Equal(t, AuthError, authenticate(b, 0, "r", "", nil))
		require.Contains(t, b.String(), "connect: no such file or directory")
	})
}

func TestBadCA(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "badca")
		WithSSHAgent(func(a agent.Agent) {
			k, e := rsa.GenerateKey(rand.Reader, 1024)
			require.NoError(t, e)
			require.NoError(t, a.Add(agent.AddedKey{PrivateKey: k}))
			require.Equal(t, AuthError, authenticate(new(bytes.Buffer), 0, "", ca, nil))
		})
	})
}

func TestAuthorize_NoKeys(t *testing.T) {
	WithTempDir(func(dir string) {
		p := map[string]struct{}{"group:t": {}}

		ca := path.Join(dir, "ca")
		k, e := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, e)
		pub, e := ssh.NewPublicKey(&k.PublicKey)
		require.NoError(t, e)
		e = ioutil.WriteFile(ca, ssh.MarshalAuthorizedKey(pub), 0444)

		WithSSHAgent(func(a agent.Agent) {
			r := authenticate(new(bytes.Buffer), 0, "", ca, p)
			require.Equal(t, AuthError, r)
		})
	})
}

func TestPamAuthorize(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "ca")
		caPamOpt := fmt.Sprintf("ca_file=%s", ca)
		principals := path.Join(dir, "principals")

		k, e := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, e)
		signer, e := ssh.NewSignerFromKey(k)
		require.NoError(t, e)
		e = ioutil.WriteFile(ca, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0444)

		userPriv, e := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, e)
		userPub, e := ssh.NewPublicKey(&userPriv.PublicKey)
		require.NoError(t, e)
		c := signedCert(userPub, signer, "foober", []string{"group:foober"})

		e = ioutil.WriteFile(principals, []byte("group:foober"), 0444)
		require.NoError(t, e)

		WithSSHAgent(func(a agent.Agent) {
			a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c})

			// test with no principal
			r := pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt})
			require.Equal(t, AuthSuccess, r,
				"authenticate failed when it should've succeeded")

			// test that the wrong principal fails
			r = pamAuthenticate(new(bytes.Buffer), getUID(), "duber", []string{caPamOpt})
			require.Equal(t, AuthError, r)

			// negative test with authorized_principals pam 2option
			r = pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt,
				fmt.Sprintf("authorized_principals=group:boober")})
			require.Equal(t, AuthError, r)

			// positive test with authorized_principals_file pam option
			r = pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt,
				fmt.Sprintf("authorized_principals_file=%s", principals)})
			require.Equal(t, AuthSuccess, r)

			// negative test with a bad authorized_principals_file pam option
			r = pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt,
				"authorized_principals_file=foober"})
			require.Equal(t, AuthError, r)

			// test that a user not in the required group passes.
			r = pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt,
				"group=nosuchgroup"})
			require.Equal(t, AuthSuccess, r)
		})

		c2 := signedCert(userPub, signer, "user", []string{"group:foober"})
		WithSSHAgent(func(a agent.Agent) {
			a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c2})

			// test without requiring the user principal
			r := pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt, "no_require_user_principal", "authorized_principals=group:foober"})
			require.Equal(t, AuthSuccess, r,
				"authenticate failed but no_require_user_principal was true")

			// test without requiring the user principal
			r = pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt, "authorized_principals=group:foober"})
			require.Equal(t, AuthError, r,
				"authenticate succeeded despite require_user_principal")
		})
	})
}

func signedCert(pubKey ssh.PublicKey, signer ssh.Signer, u string, p []string) *ssh.Certificate {
	c := &ssh.Certificate{
		ValidPrincipals: []string{u},
		Key:             pubKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		ValidAfter:      uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(1 * time.Minute).Unix()),
	}

	if p != nil {
		c.ValidPrincipals = append(c.ValidPrincipals, p...)
	}

	if e := c.SignCert(rand.Reader, signer); e != nil {
		panic(e)
	}
	return c
}

// WithTempDir runs the func `fn` with the given temporary directory.
// 'Borrowed' from cerberus.
func WithTempDir(fn func(dir string)) {
	dir, err := ioutil.TempDir("", "ussh-test")
	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	defer os.Chdir(cwd)
	os.Chdir(dir)

	fn(dir)
}

func WithSSHAgent(fn func(agent.Agent)) {
	a := agent.NewKeyring()
	WithTempDir(func(dir string) {
		newAgent := path.Join(dir, "agent")
		oldAgent := os.Getenv("SSH_AUTH_SOCK")
		os.Setenv("SSH_AUTH_SOCK", newAgent)
		defer os.Setenv("SSH_AUTH_SOCK", oldAgent)

		l, e := net.Listen("unix", newAgent)
		if e != nil {
			panic(e)
		}

		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					panic(e)
				}
				go func() {
					defer c.Close()
					agent.ServeAgent(a, c)
				}()
			}
		}()

		fn(a)
	})
}

func TestWithWrongCA(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "ca")
		caPamOpt := fmt.Sprintf("ca_file=%s", ca)

		// The correct CA is written to file for the pamAuthenticate function
		correctCAKey, e := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, e)
		correctCAPub, e := ssh.NewPublicKey(&correctCAKey.PublicKey)
		require.NoError(t, e)
		e = ioutil.WriteFile(ca, ssh.MarshalAuthorizedKey(correctCAPub), 0444)

		// The wrong CA is just used for signing the certificate
		wrongCAKey, e := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, e)
		wrongSigner, e := ssh.NewSignerFromKey(wrongCAKey)
		require.NoError(t, e)

		// Generate a user keypair
		userPriv, e := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, e)
		userPub, e := ssh.NewPublicKey(&userPriv.PublicKey)
		require.NoError(t, e)

		// Sign the user keypair with the wrong CA and try to verify it
		c := signedCert(userPub, wrongSigner, "foober", []string{"group:foober"})
		WithSSHAgent(func(a agent.Agent) {
			a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c})
			r := pamAuthenticate(new(bytes.Buffer), getUID(), "foober", []string{caPamOpt})
			require.Equal(t, AuthError, r, "authenticate succeeded when it should have failed")
		})
	})
}
