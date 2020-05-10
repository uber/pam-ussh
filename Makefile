MODULE := pam_ussh

module: test
	GOPATH=${PWD}/.go go build -buildmode=c-shared -o ${MODULE}.so

test: *.go
	go test -cover

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h

.PHONY: test module download_deps clean
