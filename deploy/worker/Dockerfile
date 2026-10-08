# Donor worker image: static cxw binary on distroless, non-root.
# Build context = repository root:  docker build -f deploy/worker/Dockerfile .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cxw ./cmd/cxw && mkdir -p /out/cache

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cxw /cxw
# Mount point of the cxw-cache volume; its ownership seeds a fresh named volume so the
# non-root worker can write compiled code, pinned modules and its key there.
COPY --from=build --chown=65532:65532 /out/cache /cache
USER nonroot:nonroot
ENTRYPOINT ["/cxw"]
