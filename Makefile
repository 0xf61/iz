.PHONY: build test install linux clean

build:
	go build -o iz .

test:
	go test ./...

install: build
	cp iz ~/.local/bin/iz
	-codesign -s - -f ~/.local/bin/iz 2>/dev/null # macOS: re-sign after copy

linux:
	GOOS=linux GOARCH=amd64 go build -o dist/iz-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o dist/iz-linux-arm64 .

clean:
	rm -rf iz dist
