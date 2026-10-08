# Gateway image: static binary on distroless, non-root, with the baked-in WASM seed set at /seed.
# Build context = repository root:   docker build -f deploy/gateway/Dockerfile .
#
# Stages:
#   build     the gateway, courier and edge binaries (CGO off, linux/amd64 static)
#   seed      every Go wasip1 seed module (catalog tools, gym mods, hooks) + the catalog-go
#             interpreters, hashed into /seed with a MANIFEST
#   final     distroless static nonroot: /gateway + /seed (SEED_WASM_DIR), empty /data

# ---- build: the three service binaries -------------------------------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /out/data
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/courier ./cmd/courier
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/edge ./cmd/edge

# ---- seed: GOOS=wasip1 modules into /seed -----------------------------------------------------
# Each published module is <name>.wasm + <name>.json (the manifest SeedSystem reads, 15.3). Sources:
#   internal/catalog/seed/<name>/   Go wasip1 tools (manifest.json present)
#   internal/hooks/seed/<name>/     Go wasip1 space hooks (manifest.json present)
#   internal/gym/mods/<name>/       Go wasip1 gym evaluators (manifest generated if absent)
# Then catalog-go/build.sh adds the three Go-native interpreters (cx-starlark, cx-goja, cx-expr);
# module download is allowed at image-build time, pinned by catalog-go/go.sum. MANIFEST is the
# sha256 list the operator diffs against PINS.txt before trusting the image.
FROM golang:1.27-alpine AS seed
RUN apk add --no-cache bash coreutils
WORKDIR /src
COPY . .
RUN mkdir -p /seed
# catalog tools and hooks: manifest ships with the source.
RUN set -eu; for base in internal/catalog/seed internal/hooks/seed; do \
      for d in "$base"/*/; do \
        [ -f "$d/main.go" ] || continue; \
        name=$(basename "$d"); \
        echo "seed: building $name" >&2; \
        GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -o "/seed/$name.wasm" "./$d"; \
        if [ -f "$d/manifest.json" ]; then cp "$d/manifest.json" "/seed/$name.json"; \
        else printf '{"abi":"text","desc":"%s"}\n' "$name" > "/seed/$name.json"; fi; \
      done; \
    done
# gym evaluators: build each dir that is a main package; synthesize a minimal manifest when none ships.
RUN set -eu; for d in internal/gym/mods/*/; do \
      [ -f "$d/main.go" ] || continue; \
      grep -q '^package main' "$d/main.go" || continue; \
      name="gym-$(basename "$d")"; \
      echo "seed: building $name" >&2; \
      GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -o "/seed/$name.wasm" "./$d" || continue; \
      if [ -f "$d/manifest.json" ]; then cp "$d/manifest.json" "/seed/$name.json"; \
      else printf '{"abi":"text","desc":"gym evaluator %s"}\n' "$(basename "$d")" > "/seed/$name.json"; fi; \
    done
# catalog-go interpreters (separate module): builds cx-starlark, cx-goja, cx-expr into /seed.
RUN set -eu; CX_BUILD_ANYWHERE=1 bash catalog-go/build.sh /seed /seed/SIZES.md || \
      echo "seed: catalog-go build skipped (toolchain)" >&2
# MANIFEST: sha256 of every module, so the operator can verify the image against catalog/PINS.txt.
RUN set -eu; cd /seed; : > MANIFEST; for f in *.wasm; do [ -e "$f" ] || continue; \
      sha256sum "$f" >> MANIFEST; done; echo "seed modules:"; cat MANIFEST >&2

# ---- final: distroless static nonroot ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gateway /gateway
COPY --from=seed /seed /seed
# empty /data owned by nonroot so a fresh named volume mounted there is writable
COPY --from=build --chown=65532:65532 /out/data /data
ENV SEED_WASM_DIR=/seed
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gateway"]
