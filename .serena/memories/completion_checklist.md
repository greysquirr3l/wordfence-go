# Task Completion Checklist

Before marking a task as complete, verify:

## Code Quality

- [ ] Code compiles without errors: `go build ./...`
- [ ] All tests pass: `go test ./...`
- [ ] No lint issues: `golangci-lint run`
- [ ] Code is formatted: `go fmt ./...`

## Testing

- [ ] Unit tests added for new functionality
- [ ] Edge cases covered
- [ ] Error paths tested

## Documentation

- [ ] Exported types/functions have doc comments
- [ ] Complex logic has inline comments
- [ ] README updated if needed

## Build Verification

- [ ] Static binary builds: `CGO_ENABLED=0 go build -o bin/wordfence ./cmd/wordfence`
- [ ] Cross-compilation works: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`

## Quick Check Commands

```bash
# Full verification
go build ./... && go test ./... && go vet ./... && golangci-lint run

# Quick check
go build ./... && go test -short ./...
```
