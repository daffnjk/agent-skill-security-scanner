.PHONY: build test selftest action-test verify release

GOOS ?= linux
GOARCH ?= amd64

build:
	CGO_ENABLED=0 go build -trimpath -o skillscan ./cmd/detector

test:
	go test ./...
	PYTHONPATH=scripts python3 -m unittest scripts/test_github_action_gate.py

selftest:
	./scripts/selftest.sh

action-test:
	PYTHONPATH=scripts python3 -m unittest scripts/test_github_action_gate.py

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	./scripts/selftest.sh
	PYTHONPATH=scripts python3 -m unittest scripts/test_github_action_gate.py

release:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -buildid=" -o skillscan-$(GOOS)-$(GOARCH) ./cmd/detector
