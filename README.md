Uber's SSH certificate pam module.

This is a pam module that will authenticate a user based on them having an ssh certificate in
their ssh-agent signed by a specified ssh CA.

Works on linux and osx. BSD doesn't work because go doesn't (yet) support `buildmode=c-shared`
on bsd.

Building:

1. clone the repo and run 'make'
```
  $ git clone github.com/uber/pam-ussh

  ...

  $ make
  mkdir -p /home/pmoody/tmp/pam-ussh/.go/src
  GOPATH=/home/pmoody/tmp/pam-ussh/.go go get golang.org/x/crypto/ssh
  GOPATH=/home/pmoody/tmp/pam-ussh/.go go get golang.org/x/crypto/ssh/agent
  GOPATH=/home/pmoody/tmp/pam-ussh/.go go get github.com/stretchr/testify/require
  GOPATH=/home/pmoody/tmp/pam-ussh/.go go test -cover
  PASS
  coverage: 71.8% of statements
  ok  	_/home/pmoody/tmp/pam-ussh	0.205s
  GOPATH=/home/pmoody/tmp/pam-ussh/.go go build -buildmode=c-shared -o pam_ussh.so

  $
```

Usage:
1. put this pam module where ever pam modules live on your system, eg. /lib/security

2. add it as an authentication method, eg.

```
  $ grep auth /etc/pam.d/sudo
  auth [success=1 default=ignore] /lib/security/pam_ussh.so
  auth requisite                  pam_deny.so
  auth required                   pam_permit.so
```

Runtime configuration options:
* `ca_file` - string, the path to your TrustedUserCAKeys file, default `/etc/ssh/trusted_user_ca`.
  This is the pubkey that signs your user certificates.

* `authorized_principals` - string, comma separated list of authorized principals, default `""`.
  If set, the user needs to have a principal in this list in order to use this module. If
  this and `authorized_principals_file` are both set, only the last option listed is checked.

* `authorized_principals_file` - string, path to an authorized_principals file, default `""`.
  If set, users need to have a principal listed in this file in order to use this module.
  If this and `authorized_principals` are both set, only the last option listed is checked.

* `group` - string, default, `""`
  If set, the user needs to be a member of this group in order to use this module.


Example configuration:

the following looks for a certificate on $SSH_AUTH_SOCK that have been signed by user_ca. Additionally,
the user needs to have a principal on the certificate that's listed in /etc/ssh/root_authorized_principals

```
auth [success=1 default=ignore] /lib/security/pam_ussh.so ca_file=/etc/ssh/user_ca authorized_principals_file=/etc/ssh/root_authorized_principals
```

FAQ:

* does this work with non-certificate ssh-keys?
  A: no, not at the moment. there's no reason it can't though, we just didn't need it to do that so I never added the functionality.

* why aren't you using $DEP_SYSTEM?
  A: we didn't need to so we didn't bother.

* can you make it do $X?
  A: submit a feature request, or better yet a pull request.

Information on ssh certificates:
* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD
* https://blog.habets.se/2011/07/OpenSSH-certificates.html
