.PHONY: build test selftest release

build:
	CGO_ENABLED=0 go build -trimpath -o skillscan ./cmd/detector

test:
	go test ./...

selftest:
	./scripts/selftest.sh

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o skillscan-linux-amd64 ./cmd/detector
