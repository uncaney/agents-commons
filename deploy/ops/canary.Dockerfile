# Canary image: bash + curl + the cx CLI + test/canary.sh. Build context = repository root:
#   docker build -f deploy/ops/canary.Dockerfile -t ekaii/commons-canary:latest .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cx ./cmd/cx

FROM alpine:3.21
RUN apk add --no-cache bash curl ca-certificates coreutils
COPY --from=build /out/cx /usr/local/bin/cx
COPY test/canary.sh /usr/local/bin/canary.sh
RUN chmod 0755 /usr/local/bin/canary.sh /usr/local/bin/cx && mkdir -p /state && chown 65532:65532 /state
USER 65532:65532
ENV CX_BIN=/usr/local/bin/cx CANARY_STATE=/state HOME=/tmp
ENTRYPOINT ["/usr/local/bin/canary.sh"]
