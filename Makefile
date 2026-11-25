.PHONY: build test install linux dist clean

LDFLAGS := -s -w
GOFLAGS := -trimpath

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o iz .

test:
	go test -race ./...

install: build
	cp iz ~/.local/bin/iz
	-codesign -s - -f ~/.local/bin/iz 2>/dev/null # macOS: re-sign after copy

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/iz-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/iz-linux-arm64 .

dist: linux
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/iz-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/iz-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/iz-windows-amd64.exe .

clean:
	rm -rf iz dist
