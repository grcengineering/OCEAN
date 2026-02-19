BINARY_NAME=ocean
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-s -w -X github.com/grcengineering/ocean/internal/cli.version=$(VERSION) -X github.com/grcengineering/ocean/internal/cli.buildTime=$(BUILD_TIME)"

# Cross-compile target platforms
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Test configuration
COVERAGE_THRESHOLD ?= 70

.PHONY: build test test-unit test-integration test-e2e test-all test-json \
        lint run install clean cross-compile release coverage coverage-check \
        coverage-report docker

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/ocean

test:
	go test -race -coverprofile=coverage.out ./...

# Unit tests only (fast, no external deps, no build tags)
test-unit:
	go test -race -count=1 -coverprofile=coverage.out ./...

# Integration tests (require //go:build integration tag)
test-integration:
	go test -race -count=1 -tags=integration ./...

# End-to-end tests (require //go:build e2e tag)
test-e2e:
	go test -race -count=1 -tags=e2e ./...

# All test tiers
test-all:
	go test -race -count=1 -tags="integration e2e" -coverprofile=coverage.out ./...

# Machine-parseable JSON output (for CI)
test-json:
	go test -race -count=1 -json ./... 2>&1

lint:
	golangci-lint run ./...

run: build
	./$(BINARY_NAME)

install:
	go install $(LDFLAGS) ./cmd/ocean

clean:
	rm -f $(BINARY_NAME) coverage.out coverage.html
	rm -rf dist/bin/

# Cross-compile for all target platforms
cross-compile:
	@mkdir -p dist/bin
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		SUFFIX=""; \
		if [ "$${platform%/*}" = "windows" ]; then SUFFIX=".exe"; fi; \
		echo "Building $${platform%/*}/$${platform#*/}..."; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} go build $(LDFLAGS) \
			-o dist/bin/$(BINARY_NAME)-$${platform%/*}-$${platform#*/}$${SUFFIX} \
			./cmd/ocean || exit 1; \
	done
	@echo "Cross-compilation complete. Binaries in dist/bin/"

# Build release binary for current platform (stripped)
release:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/ocean

coverage: test
	go tool cover -html=coverage.out -o coverage.html

# Coverage with threshold enforcement
coverage-check: test-unit
	@go tool cover -func=coverage.out | tail -1 | awk '{ gsub(/%/, "", $$3); if ($$3+0 < $(COVERAGE_THRESHOLD)) { print "FAIL: coverage " $$3 "% below threshold $(COVERAGE_THRESHOLD)%"; exit 1 } else { print "OK: coverage " $$3 "% meets threshold $(COVERAGE_THRESHOLD)%" } }'

# Per-package coverage breakdown
coverage-report: test-unit
	@go tool cover -func=coverage.out

# Build Docker image
docker:
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .
