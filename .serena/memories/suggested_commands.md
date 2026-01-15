# Suggested Commands for wordfence-go

## Build Commands

```bash
# Build for current platform
make build

# Build static binary for Linux x86_64
make build-linux-amd64

# Build for all platforms
make build-all

# Quick build during development
go build -o bin/wordfence ./cmd/wordfence
```

## Test Commands

```bash
# Run all tests
make test
# or
go test -race -cover ./...

# Run tests with verbose output
go test -v ./...

# Run specific package tests
go test -v ./internal/scanner/...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Lint & Format Commands

```bash
# Run linter
make lint
# or
golangci-lint run

# Format code
go fmt ./...
gofmt -s -w .

# Vet code
go vet ./...
```

## Development Commands

```bash
# Initialize module (first time only)
go mod init github.com/nickcampbell/wordfence-go

# Add dependencies
go get github.com/spf13/cobra
go get github.com/dlclark/regexp2

# Tidy dependencies
go mod tidy

# Run directly
go run ./cmd/wordfence version
go run ./cmd/wordfence malware-scan /path/to/scan
```

## Git Commands (macOS/Darwin)

```bash
git status
git add -A
git commit -m "message"
git push origin main
git log --oneline -10
```

## System Commands (Darwin/macOS)

```bash
ls -la
find . -name "*.go" -type f
grep -r "pattern" --include="*.go" .
tree -L 2  # requires: brew install tree
```
