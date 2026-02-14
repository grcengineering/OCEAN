BINARY_NAME=ocean
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-s -w -X github.com/grcengineering/ocean/internal/cli.version=$(VERSION) -X github.com/grcengineering/ocean/internal/cli.buildTime=$(BUILD_TIME)"

# Cross-compile target platforms
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: build test lint run install clean cross-compile release coverage docker

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/ocean

test:
	go test -race -coverprofile=coverage.out ./...

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

# Build Docker image
docker:
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .
