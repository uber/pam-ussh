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

// code in here can't be tested because it relies on cgo. :(

import (
	"unsafe"
)

/*
#cgo LDFLAGS: -lpam -fPIC
#include <security/pam_appl.h>
#include <stdlib.h>

char *string_from_argv(int, char**);
char *get_user(pam_handle_t *pamh);
char *get_authtok(pam_handle_t *pamh);
int get_uid(char *user);
int set_user(pam_handle_t *pamh, const char *user);
int define_var(pam_handle_t *pamh, char *name, char *val);
int undefine_var(pam_handle_t *pamh, char *name);
*/
import "C"

func init() {
	if !disablePtrace() {
		pamLog("unable to disable ptrace")
	}
}

func sliceFromArgv(argc C.int, argv **C.char) []string {
	r := make([]string, 0, argc)
	for i := 0; i < int(argc); i++ {
		s := C.string_from_argv(C.int(i), argv)
		defer C.free(unsafe.Pointer(s))
		r = append(r, C.GoString(s))
	}
	return r
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	envName := C.CString("PAM_JWT_AUTH")
	envValYes := C.CString("1")
	envValNo := C.CString("0")
	defer C.free(unsafe.Pointer(envName))
	defer C.free(unsafe.Pointer(envValYes))
	defer C.free(unsafe.Pointer(envValNo))

	C.define_var(pamh, envName, envValNo)

	cUsername := C.get_user(pamh)
	if cUsername == nil {
		return C.PAM_USER_UNKNOWN
	}
	defer C.free(unsafe.Pointer(cUsername))

	cAuthToken := C.get_authtok(pamh)
	defer C.free(unsafe.Pointer(cAuthToken))

	authToken := C.GoString(cAuthToken)
	userName := C.GoString(cUsername)

	name, r := pamAuthenticate(userName, authToken, sliceFromArgv(argc, argv))
	if r == AuthError {
		return C.PAM_AUTH_ERR
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	uid := int(C.get_uid(cName))
	if uid < 0 {
		return C.PAM_USER_UNKNOWN
	}

	if name != userName {
		C.set_user(pamh, cName)
	}

	C.define_var(pamh, envName, envValYes)
	return C.PAM_SUCCESS
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_IGNORE
}
