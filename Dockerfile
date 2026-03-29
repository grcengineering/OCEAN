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

# Stage 2: Distroless production image
# gcr.io/distroless/cc-debian12 includes glibc + libgcc for dynamically-linked
# Rust binaries, plus CA certificates for outbound HTTPS API calls.
# No shell, no package manager, no OS utilities — minimal attack surface.
FROM gcr.io/distroless/cc-debian12

LABEL org.opencontainers.image.title="OCEAN" \
      org.opencontainers.image.description="Open Control Evidence Assessment Normalizer" \
      org.opencontainers.image.url="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.source="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/release/ocean /usr/local/bin/ocean

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ocean"]
CMD ["serve", "--port", "8080"]
