BIN := pfsense-unifi-agent

.PHONY: test build build-freebsd clean

test:
	go test -v ./...

build:
	go build -o bin/$(BIN) ./cmd/pfsense-unifi-agent

build-freebsd:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/$(BIN)-freebsd-amd64 ./cmd/pfsense-unifi-agent

clean:
	rm -rf bin
