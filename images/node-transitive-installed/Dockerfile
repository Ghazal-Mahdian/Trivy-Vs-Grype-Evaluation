# Test case: vulnerable TRANSITIVE npm dependency, installed layout.
# Direct dependency mkdirp 0.5.1 pulls in minimist 0.0.8 (two advisories; see
# ground-truth/node-transitive-installed.json, written before any scan).
#
# The build stage installs the packages; the final image keeps ONLY
# /app/node_modules (no package.json, no lockfile at the top level), like a
# typical multi-stage production image. The only evidence of what is inside is
# the installed package.json files under node_modules.
#
# The build stage is pinned by index digest. The final stage is the same pinned
# distroless static base as images/minimal-base-pass, so the OS layer adds
# nothing new and no Node runtime (nothing is run). Build and scan with
# --platform=linux/amd64. `npm ls --all` prints the resolved tree into the build
# log as evidence (build with --progress=plain to see it).
FROM node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS build
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm ls --all

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /app/node_modules /app/node_modules
