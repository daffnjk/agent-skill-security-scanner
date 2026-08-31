# Compact, deterministic agent-skill security scanner image.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o /skillscan ./cmd/detector

FROM busybox:1.36-musl
COPY --from=build /skillscan /skillscan
RUN mkdir -p /output /data/skills && chown -R 1000:0 /output /data
USER 1000
ENTRYPOINT ["/skillscan"]
