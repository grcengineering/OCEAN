# Stage 1: Build
FROM rust:bookworm AS builder

WORKDIR /build

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    printf "" > src/lib.rs && \
    cargo build --release 2>/dev/null; \
    rm -rf src

# Build the real binary
COPY src ./src
RUN touch src/main.rs src/lib.rs && \
    cargo build --release

# Stage 2: Minimal production image
FROM debian:bookworm-slim

# CA certs for HTTPS API calls
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="OCEAN" \
      org.opencontainers.image.description="Open Control Evidence Assessment Normalizer" \
      org.opencontainers.image.url="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.source="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/release/ocean /usr/local/bin/ocean

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/ocean", "version"]

ENTRYPOINT ["/usr/local/bin/ocean"]
CMD ["serve", "--port", "8080"]
