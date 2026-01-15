# Go Style and Conventions for wordfence-go

## Code Style

### Naming Conventions

- **Packages**: lowercase, single word (e.g., `scanner`, `cache`, `api`)
- **Exported**: PascalCase (e.g., `ScanResult`, `NewScanner`)
- **Unexported**: camelCase (e.g., `workerCount`, `processFile`)
- **Constants**: PascalCase for exported, camelCase for unexported
- **Interfaces**: Usually end with `-er` suffix (e.g., `Scanner`, `Matcher`)

### File Organization

- One primary type per file when possible
- Test files: `*_test.go` in same package
- Internal packages in `internal/` directory
- Shared/public packages in `pkg/` directory

### Error Handling

```go
// Return errors, don't panic
func DoSomething() error {
    if err := step1(); err != nil {
        return fmt.Errorf("step1 failed: %w", err)
    }
    return nil
}

// Custom errors when needed
var ErrNotFound = errors.New("not found")
```

### Comments

- Package comments on package declaration
- Exported functions/types must have doc comments
- Use `// TODO:` for future work

```go
// Package scanner provides malware scanning functionality.
package scanner

// Scanner scans files for malware signatures.
type Scanner struct { ... }

// Scan scans the given paths for malware.
func (s *Scanner) Scan(ctx context.Context, paths []string) error { ... }
```

## Project Patterns

### Dependency Injection

- Pass dependencies via constructors
- Use interfaces for testability

```go
type Scanner struct {
    signatures SignatureProvider
    cache      Cache
}

func NewScanner(sigs SignatureProvider, cache Cache) *Scanner {
    return &Scanner{signatures: sigs, cache: cache}
}
```

### Context Usage

- First parameter for cancelable operations
- Propagate through call chain

```go
func (s *Scanner) Scan(ctx context.Context, path string) error {
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
        // continue scanning
    }
}
```

### Concurrency

- Use goroutines + channels for worker pools
- Prefer sync.WaitGroup for coordination
- Always handle context cancellation

## Dependencies

### Required

- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration
- `github.com/dlclark/regexp2` - PCRE-compatible regex

### Optional

- `github.com/fatih/color` - Colored output
- `gopkg.in/ini.v1` - INI file parsing
