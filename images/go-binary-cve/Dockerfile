# Test case: Go binary (vulnerable modules recorded only in the binary's build info)
# No package manager metadata exists in the final image: the only evidence of
# what is inside is the module list embedded in /app. See
# ground-truth/go-binary-cve.json for the answer key (written before any scan).
#
#   github.com/dgrijalva/jwt-go v3.2.0+incompatible  -> CVE-2020-26160, no fix in the v3 line
#   github.com/gorilla/websocket v1.4.2              -> GHSA-w67g-5rqw-f597 (no CVE), fixed in 1.5.3
#   gopkg.in/yaml.v3 v3.0.1                          -> clean control
#
# Build stage pinned by index digest (golang:1.26 as of 2026-11-13). The final
# stage is the same pinned distroless base as images/minimal-base-pass, so the
# OS layer adds nothing new. Build and scan with --platform=linux/amd64.
# `go version -m` prints the embedded module list into the build log as evidence
# (build with --progress=plain to see it).
FROM golang:1.26@sha256:978e0a4e3d953662577d784471db27742f543ab09eead06839a838188c73314b AS build
WORKDIR /src
COPY go.mod main.go ./
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN go mod tidy && go build -o /out/app . && go version -m /out/app

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
