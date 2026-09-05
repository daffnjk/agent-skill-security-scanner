# The build workflow resolves this exact version to a registry digest.
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VCS_REF=unknown
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w -buildid= -X main.buildCommit=$VCS_REF" -o /skillscan ./cmd/detector
RUN mkdir -p /runtime/output /runtime/data/skills

# The scanner is static and offline; no shell or package manager is required.
FROM scratch
COPY --from=build /skillscan /skillscan
COPY --from=build --chown=1000:0 /runtime/ /
USER 1000
ENTRYPOINT ["/skillscan"]
