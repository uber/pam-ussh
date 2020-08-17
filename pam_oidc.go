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
	"fmt"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"log"
	"log/syslog"
	"runtime"
	"strings"
	"time"
)

// AuthResult is the result of the authenticate function.
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
func authenticate(username, authToken, secret, signingKey, alg, issuer, domain string) (string, AuthResult) {
	if authToken == "" {
		authToken = username
	}

	standard := jwt.Claims{}
	if len(secret) > 0 && len(signingKey) > 0 {
		enc, err := jwt.ParseSignedAndEncrypted(authToken)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return "", AuthError
		}
		token, err := enc.Decrypt(secret)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return "", AuthError
		}
		if _, err := verifyAlg(token.Headers, alg); err != nil {
			log.Printf("signature validation failure: %s", err)
			return "", AuthError
		}
		if err = token.Claims(signingKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return "", AuthError
		}
	} else if len(signingKey) == 0 {
		token, err := jwt.ParseEncrypted(authToken)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return "", AuthError
		}
		err = token.Claims(secret, &standard)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return "", AuthError
		}
	} else {
		token, err := jwt.ParseSigned(authToken)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return "", AuthError
		}
		if _, err := verifyAlg(token.Headers, alg); err != nil {
			log.Printf("signature validation failure: %s", err)
			return "", AuthError
		}
		err = token.Claims(signingKey, &standard)
		if err = token.Claims(signingKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return "", AuthError
		}
	}

	// go-jose doesnt verify the expiry
	err := standard.Validate(jwt.Expected{
		Issuer: issuer,
		Time: time.Now(),
	})

	if err != nil {
		log.Printf("token validation failed due to %s", err)
		return "", AuthError
	}

	return standard.Subject+domain, AuthSuccess
}

func pamAuthenticate(username string, authToken string, argv []string) (string, AuthResult) {
	runtime.GOMAXPROCS(1)

	var alg string
	var secret string
	var issuer string
	var domain string
	var signingKey string

	for _, arg := range argv {
		opt := strings.Split(arg, "=")
		switch opt[0] {
		case "secret":
			secret = opt[1]
			pamLog("secret set")
		case "signing_key":
			secret = opt[1]
			pamLog("signing key set")
		case "alg":
			alg = opt[1]
			pamLog("alg is set to %s", alg)
		case "issuer":
			issuer = opt[1]
			pamLog("issuer is set to %s", issuer)
		case "domain":
			domain = opt[1]
			pamLog("domain is set to %s", domain)
		default:
			pamLog("unkown option: %s\n", opt[0])
		}
	}

	if len(secret) == 0 && (len(signingKey) == 0 || len(alg) == 0) {
		pamLog("secret and/or signing_key+alg not set")
		return "", AuthError
	}

	return authenticate(username, authToken, secret, signingKey, alg, issuer, domain)
}

func verifyAlg(headers []jose.Header, alg string) (bool, error) {
	for _, header := range headers {
		if header.Algorithm != alg {
			return false, fmt.Errorf("invalid signing method %s", header.Algorithm)
		}
	}
	return true, nil
}

func main() {}
