.PHONY: build test selftest verify release

GOOS ?= linux
GOARCH ?= amd64

build:
	CGO_ENABLED=0 go build -trimpath -o skillscan ./cmd/detector

test:
	go test ./...

selftest:
	./scripts/selftest.sh

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	./scripts/selftest.sh

release:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -buildid=" -o skillscan-$(GOOS)-$(GOARCH) ./cmd/detector
