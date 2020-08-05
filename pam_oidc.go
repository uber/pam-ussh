// +build darwin linux

/*
Copyright (c) 2017 Uber Technologies, Inc.
Copyright (c) 2020 Bolke de Bruin

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
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"log/syslog"
	"runtime"
	"strings"
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
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "pam-oidc")
	if err != nil {
		return
	}
	l.Warning(fmt.Sprintf(format, args...))
}

// authenticate validates the token
func authenticate(uid int, username, authToken, clientId, providerUrl string) (string, AuthResult) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, providerUrl)
	if err != nil {
		pamLog("cannot get oidc provider due to %s", err)
		return "", AuthError
	}
	if authToken == "" {
		authToken = username
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientId})
	idToken, err := verifier.Verify(ctx, authToken)
	if err != nil {
		pamLog("token verification failed: %s", err)
		return "", AuthError
	}

	return idToken.Subject, AuthSuccess
}

func pamAuthenticate(uid int, username string, authToken string, argv []string) (string, AuthResult) {
	runtime.GOMAXPROCS(1)

	var clientId string
	var providerUrl string

	for _, arg := range argv {
		opt := strings.Split(arg, "=")
		switch opt[0] {
		case "client_id":
			clientId = opt[1]
			pamLog("client id set to %s", clientId)
		case "provider_url":
			providerUrl = opt[1]
			pamLog("provider url set to %s", providerUrl)
		default:
			pamLog("unkown option: %s\n", opt[0])
		}
	}

	if len(clientId) == 0 || len(providerUrl) == 0 {
		pamLog("client_id and/or provider_url not set")
		return "", AuthError
	}

	return authenticate(uid, username, authToken, clientId, providerUrl)
}

func main() {}
