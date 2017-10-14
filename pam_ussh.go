// +build darwin linux

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
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"os"
	"path"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	defaultUserCA = "/etc/ssh/trusted_user_ca"
	defaultGroup  = ""
)

// AuthResult is the result of the authentcate function.
type AuthResult int

const (
	// AuthError is a failure.
	AuthError AuthResult = iota
	// AuthSuccess is a success.
	AuthSuccess
)

func pamLog(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "pam-ussh")
	if err != nil {
		return
	}
	l.Warning(fmt.Sprintf(format, args...))
}

// authenticate validates certs loaded on the ssh-agent at the other end of
// AuthSock.
func authenticate(w io.Writer, uid int, username, ca string, principals map[string]struct{}) AuthResult {
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		fmt.Fprint(w, "No SSH_AUTH_SOCK")
		return AuthError
	}

	origEUID := os.Geteuid()
	if os.Getuid() != origEUID || origEUID == 0 {
		// Note: this only sets the euid and doesn't do anything with the egid.
		// That should be fine for most cases, but it's worth calling out.
		if !seteuid(uid) {
			pamLog("error dropping privs from %d to %d", origEUID, uid)
			return AuthError
		}
		defer func() {
			if !seteuid(origEUID) {
				pamLog("error resetting uid to %d", origEUID)
			}
		}()
	}

	agentSock, err := net.Dial("unix", authSock)
	if err != nil {
		fmt.Fprintf(w, "error connecting to %s: %v\n", authSock, err)
		// if we're here, we probably can't stat the socket to get the owner uid
		// to decorate the logs, but we might be able to read the parent directory.
		ownerUID := ownerUID(path.Dir(authSock))
		pamLog("error opening auth sock (sock owner: %d/%s) by (caller: %d/%s)",
			ownerUID, getUsername(ownerUID), os.Getuid(), username)
		return AuthError
	}

	a := agent.NewClient(agentSock)
	keys, err := a.List()
	if err != nil {
		pamLog("Error listing keys: %v", err)
		return AuthError
	}

	if len(keys) == 0 {
		pamLog("No certs loaded.\n")
		return AuthError
	}

	caBytes, err := ioutil.ReadFile(ca)
	if err != nil {
		pamLog("error reading ca: %v\n", err)
		return AuthError
	}

	caPubkey, _, _, _, err := ssh.ParseAuthorizedKey(caBytes)
	if err != nil {
		return AuthError
	}

	c := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPubkey.Marshal())
		},
	}

	for idx := range keys {
		pubKey, err := ssh.ParsePublicKey(keys[idx].Marshal())
		if err != nil {
			continue
		}

		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			continue
		}

		if err := c.CheckCert(username, cert); err != nil {
			continue
		}

		// for the ssh agent to sign some data validating that they do in fact
		// have the private key
		randBytes := make([]byte, 32)
		if _, err := rand.Read(randBytes); err != nil {
			pamLog("Error grabbing random bytes: %v\n", err)
			return AuthError
		}

		signedData, err := a.Sign(pubKey, randBytes)
		if err != nil {
			pamLog("error signing data: %v\n", err)
			return AuthError
		}

		if err := pubKey.Verify(randBytes, signedData); err != nil {
			pamLog("signature verification failed: %v\n", err)
			return AuthError
		}

		if len(principals) == 0 {
			pamLog("Authentication succeeded for %s, cert %d", cert.ValidPrincipals[0], cert.Serial)
			return AuthSuccess
		}

		for _, p := range cert.ValidPrincipals {
			if _, ok := principals[p]; ok {
				pamLog("Authentication succeded for %s. Matched principal %s, cert %d",
					cert.ValidPrincipals[0], p, cert.Serial)
				return AuthSuccess
			}
		}
	}
	pamLog("no valid certs found")
	return AuthError
}

func loadValidPrincipals(principals string) (map[string]struct{}, error) {
	f, err := os.Open(principals)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		p[scanner.Text()] = struct{}{}
	}
	return p, nil
}

func pamAuthenticate(w io.Writer, uid int, username string, argv []string) AuthResult {
	runtime.GOMAXPROCS(1)

	userCA := defaultUserCA
	group := defaultGroup
	authorizedPrincipals := make(map[string]struct{})

	for _, arg := range argv {
		opt := strings.Split(arg, "=")
		switch opt[0] {
		case "ca_file":
			userCA = opt[1]
			pamLog("ca_file set to %s", userCA)
		case "group":
			group = opt[1]
			pamLog("group set to %s", group)
		case "authorized_principals":
			for _, s := range strings.Split(opt[1], ",") {
				authorizedPrincipals[s] = struct{}{}
			}
		case "authorized_principals_file":
			ap, err := loadValidPrincipals(opt[1])
			if err != nil {
				pamLog("%v", err)
				return AuthError
			}
			authorizedPrincipals = ap
		default:
			pamLog("unkown option: %s\n", opt[0])
		}
	}

	if len(group) == 0 || isMemberOf(group) {
		return authenticate(w, uid, username, userCA, authorizedPrincipals)
	}

	return AuthSuccess
}

func main() {}
