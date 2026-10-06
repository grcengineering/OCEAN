# Stage 1: Build
# Digest-pinned: a tag can move under you, a digest cannot. Renovate keeps it current.
FROM rust:bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS builder

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

# Stage 2: Chainguard zero-CVE production image
# cgr.dev/chainguard/glibc-dynamic provides glibc, ld-linux and libgcc_s for
# dynamically-linked Rust binaries, plus the CA certificate bundle for outbound
# HTTPS API calls. No shell, no package manager, no OS utilities — minimal
# attack surface.
#
# Was cc-dynamic until 2026-09-12. cc-dynamic is no longer anonymously pullable
# (cgr.dev returns 403 FORBIDDEN on the anonymous pull token for that repository),
# so the build could not have succeeded on a runner without Chainguard credentials.
# glibc-dynamic is anonymously pullable and is a superset of what this stage needs
# (verified in the image: usr/lib/libc.so.6, usr/lib/libgcc_s.so.1,
# usr/lib/ld-linux-*.so, etc/ssl/certs/ca-certificates.crt).
#
# Digest-pinned; Chainguard rebuilds :latest continuously, so Renovate must keep
# this digest moving — a stale free-tier digest is eventually garbage-collected.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:94ec8c23c45c7aad22b6ab400dc7e1b46dd36f4c71d6c7a3976c8ad4e36ca266

LABEL org.opencontainers.image.title="OCEAN" \
      org.opencontainers.image.description="Open Control Evidence Assessment Normalizer" \
      org.opencontainers.image.url="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.source="https://github.com/grcengineering/ocean" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/release/ocean /usr/local/bin/ocean

VOLUME ["/data"]
EXPOSE 8080

USER 65532

ENTRYPOINT ["/usr/local/bin/ocean"]
CMD ["serve", "--port", "8080"]
