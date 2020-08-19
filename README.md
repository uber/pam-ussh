JWT pam module.

This is a pam module that will authenticate a user based on them having a ecnrypted and/or signed
JWT token.

This is primarily intended as an authentication module for SSO cases, like using it for connecting
RDP users to XRDP without passwords. We'd be happy to learn of other potential uses though.

An example usage would be you to use a remote desktop gateway to obtain a JWT token in a RDP file
to connect to a remote machine and XRDP authenticates you.

Works on linux and osx. BSD doesn't work because go doesn't (yet) support `buildmode=c-shared`
on bsd.

Building:

1. clone the repo and run 'make'
```
  $ git clone github.com/bolkedebruin/pam-jwt

  ...

  $ make
  go build -buildmode=c-shared -o pam_jwt.so
  go test -cover
  PASS
  coverage: 71.8% of statements
  ok  	_/home/pmoody/tmp/pam-ussh	0.205s

  $
```

Usage:

1. put this pam module where ever pam modules live on your system, eg. `/lib/security`

2. add it as an authentication method, eg.

```
  $ grep auth /etc/pam.d/xrdp-sesman
  auth sufficient                 pam_wt.so token_url=https://something?access_token= 
  # auth sufficient                 pam_jwt.so secret=<encryption_key> signing_key=<signing_key> alg=<alg> issuer=issuer
  auth include                    password-auth
```

FAQ:

* How do I report a security issue?
  - Please report security issues in the issues

* can you make it do $X?
  - Submit a feature request, or better yet a pull request
