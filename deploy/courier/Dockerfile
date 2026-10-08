# Courier image: static, stdlib-only Go binary on distroless, non-root, no exposed port (it only
# polls the gateway). Build context = repository root:
#   docker build -f deploy/courier/Dockerfile .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/courier ./cmd/courier

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/courier /courier
USER nonroot:nonroot
# No EXPOSE: nothing listens. Healthcheck = `/courier -healthcheck` (heartbeat file in /tmp).
ENTRYPOINT ["/courier"]
