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
	"github.com/dgrijalva/jwt-go/v4"
	"log/syslog"
	"runtime"
	"strings"
)

type customClaims struct {
	RemoteServer string `json:"remoteServer"`
	ClientIP	 string `json:"clientIp"`
	jwt.StandardClaims
}

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
func authenticate(uid int, username, authToken, secret, alg, issuer, domain string) (string, AuthResult) {
	token, err := jwt.ParseWithClaims(authToken, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		if alg != token.Method.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		pamLog("token verification failed: %s", err)
		return "", AuthError
	}

	if claims, ok := token.Claims.(*customClaims); ok && token.Valid {
		if issuer != "" && claims.Issuer != issuer {
			pamLog("issuer verification failed %s != %s", issuer, claims.Issuer)
			return "", AuthError
		}
		return claims.Subject+domain, AuthSuccess
	}

	return "", AuthError
}

func pamAuthenticate(uid int, username string, authToken string, argv []string) (string, AuthResult) {
	runtime.GOMAXPROCS(1)

	var alg string
	var secret string
	var issuer string
	var domain string

	for _, arg := range argv {
		opt := strings.Split(arg, "=")
		switch opt[0] {
		case "secret":
			secret = opt[1]
			pamLog("secret set")
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

	if len(secret) == 0 || len(alg) == 0 {
		pamLog("secret and/or alg not set")
		return "", AuthError
	}

	return authenticate(uid, username, authToken, secret, alg, issuer, domain)
}

func main() {}
