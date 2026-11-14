# Test case: vulnerable TRANSITIVE npm dependency, lockfile-only layout.
# Same dependency set as images/node-transitive-installed (mkdirp 0.5.1 ->
# minimist 0.0.8), but the final image contains ONLY /app/package.json and
# /app/package-lock.json: the packages are declared and locked, not installed.
# See ground-truth/node-transitive-lockfile.json (written before any scan).
#
# Whether a scanner should report a package that is declared but not installed is
# debatable, so the key marks these entries DISPUTED (counted separately). This
# image measures behavior, not a miss.
#
# Build stage pinned by index digest; final stage is the same pinned distroless
# static base as images/minimal-base-pass. Build and scan with
# --platform=linux/amd64. The lockfile is printed into the build log as evidence.
FROM node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS build
WORKDIR /app
COPY package.json ./
RUN npm install --package-lock-only --omit=dev --no-audit --no-fund && cat package-lock.json

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /app/package.json /app/package-lock.json /app/
