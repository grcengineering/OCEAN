# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/grcengineering/ocean/internal/cli.version=${VERSION} -X github.com/grcengineering/ocean/internal/cli.buildTime=${BUILD_TIME}" \
    -o ocean ./cmd/ocean

# Stage 2: Production image (scratch for minimal attack surface)
FROM scratch

LABEL org.opencontainers.image.title="OCEAN" \
      org.opencontainers.image.description="Open Control Evidence Acquisition Normalizer" \
      org.opencontainers.image.url="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.source="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy CA certificates for HTTPS API calls
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /build/ocean /ocean

# Default data directory
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/ocean", "version"]

ENTRYPOINT ["/ocean"]
CMD ["serve", "--port", "8080"]
