GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X github.com/nickcampbell/wordfence-go/internal/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/nickcampbell/wordfence-go/internal/version.BuildTime=$(BUILD_TIME) -s -w"

.PHONY: all build build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-all test lint fmt vet clean deps

all: build

# Build for current platform
build:
	go build $(LDFLAGS) -o bin/wordfence ./cmd/wordfence

# Cross-compile for Linux x86_64 (static binary)
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/wordfence-linux-amd64 ./cmd/wordfence

# Cross-compile for Linux ARM64 (static binary)
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/wordfence-linux-arm64 ./cmd/wordfence

# Cross-compile for macOS x86_64
build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/wordfence-darwin-amd64 ./cmd/wordfence

# Cross-compile for macOS ARM64
build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/wordfence-darwin-arm64 ./cmd/wordfence

# Build for all platforms
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

# Run tests with race detection and coverage
test:
	go test -race -cover ./...

# Run tests with verbose output
test-v:
	go test -race -cover -v ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...
	gofmt -s -w .

# Vet code
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Install dependencies
deps:
	go mod download
	go mod tidy
