#!/usr/bin/env bash
# Trusted harness: samples never enter the build context. No base image required.
set -euo pipefail
source_dir="$(realpath "$1")"
image="$2"
context="$(mktemp -d)"
trap 'rm -rf "$context"' EXIT
(cd "$source_dir" && env CGO_ENABLED=0 GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local \
  go build -trimpath -buildvcs=false -o "$context/skillscan" ./cmd/detector)
printf 'FROM scratch\nCOPY skillscan /skillscan\nENTRYPOINT ["/skillscan"]\n' > "$context/Dockerfile"
docker build --network=none -q -t "$image" "$context"
