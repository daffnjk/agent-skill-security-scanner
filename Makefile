.PHONY: build build-v39 test selftest selftest-v39 verify verify-v39 release release-v39 clean-v39

GOOS ?= linux
GOARCH ?= amd64

build:
	CGO_ENABLED=0 go build -trimpath -o skillscan ./cmd/detector

# v39 is shipped as an opt-in compatibility overlay plus the frozen-compatible
# base engine. Keeping a separate target makes rollout and rollback explicit.
build-v39:
	CGO_ENABLED=0 go build -trimpath -o skillscan-engine ./cmd/detector
	CGO_ENABLED=0 go build -trimpath -o skillscan-v39 ./cmd/skillscan

test:
	go test ./...

selftest:
	./scripts/selftest.sh

selftest-v39:
	bash scripts/v39-selftest.sh

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	./scripts/selftest.sh

verify-v39:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	./scripts/selftest.sh
	bash scripts/v39-selftest.sh

release:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -buildid=" -o skillscan-$(GOOS)-$(GOARCH) ./cmd/detector

release-v39:
	rm -rf dist/skillscan-v39-$(GOOS)-$(GOARCH)
	mkdir -p dist/skillscan-v39-$(GOOS)-$(GOARCH)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -buildid=" -o dist/skillscan-v39-$(GOOS)-$(GOARCH)/skillscan-engine ./cmd/detector
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -buildid=" -o dist/skillscan-v39-$(GOOS)-$(GOARCH)/skillscan-v39 ./cmd/skillscan
	tar -C dist -czf dist/skillscan-v39-$(GOOS)-$(GOARCH).tar.gz skillscan-v39-$(GOOS)-$(GOARCH)

clean-v39:
	rm -rf skillscan-engine skillscan-v39 dist/skillscan-v39-*
