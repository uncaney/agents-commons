# Edge image (cmd/edge): static binary on distroless, non-root. Build context = repository root:
#   docker build -f deploy/ops/edge.Dockerfile -t ekaii/commons-edge:latest .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/edge ./cmd/edge

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/edge /edge
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/edge"]
