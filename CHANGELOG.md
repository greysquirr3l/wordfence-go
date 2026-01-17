# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-01-17

### Added
- **Pipeline Scanner Mode** (`--pipeline` flag): Advanced scanning architecture with:
  - Staged pipeline: discover → filter → read → match → report
  - Buffer pooling with tiered sizing (4KB/64KB/1MB) for memory efficiency
  - Token bucket rate limiting for smooth I/O throttling
  - Circuit breaker protection against cascading failures
  - Idempotency support with content hashing and duplicate detection
  - Graceful shutdown with proper drain on cancellation
  - Detailed statistics per pipeline stage
- **Performance Profiles**: New `--profile` flag with predefined resource settings:
  - `gentle` - Minimal resource usage for shared/production servers
  - `balanced` - Moderate speed with reasonable resource use
  - `aggressive` - Maximum performance for dedicated servers
  - `adaptive` - Dynamically adjusts based on system conditions
- **Dynamic Resource Monitor**: Real-time monitoring using Go's `runtime/metrics` package:
  - Heap allocation and GC pressure tracking
  - Scheduler latency monitoring
  - System load average awareness (Unix)
  - Automatic throttling when resources are constrained
- **Advanced Resource Control Flags**:
  - `--memory-limit` - Pause scanning when memory exceeds threshold
  - `--io-rate-limit` - Cap disk read speed in MB/s
  - `--batch-size` / `--batch-pause` - Process files in batches with cooldown
  - `--max-load` - Pause when system load is high (Unix only)
- Basic resource control flags:
  - `--scan-delay` - milliseconds delay between files
  - `--chunk-size` - memory buffer size in KB
  - `--max-file-size` - maximum file size to scan in MB
  - `--match-timeout` - timeout for each regex match
  - `--allow-io-errors` - continue on file read errors
  - `--follow-symlinks` - follow symbolic links
- Comprehensive documentation for all resource control options in README

### Changed
- Refactored `runMalwareScan` into smaller, more maintainable functions
- Default `--match-timeout` now shown in help output (1 second)
- Default `--chunk-size` now shown in help output (1024 KB)

### Infrastructure
- **Pipeline Scanner** (`pipeline.go`): Full pipeline architecture with parallel stages
- **Token Bucket Rate Limiter** (`ratelimit.go`): Proper rate limiting with burst support for I/O operations
- **Circuit Breaker** (`circuitbreaker.go`): Prevents cascading failures when API calls fail repeatedly
- **Buffer Pool** (`bufferpool.go`): Memory-efficient buffer reuse using `sync.Pool` with tiered sizing
- **Structured Domain Errors** (`errors.go`): Rich error types with codes, retry hints, and wrapped causes

## [0.1.7] - 2026-01-16

### Fixed
- Fixed INI configuration file parsing by adding proper INI codec support
- Configuration files with `[DEFAULT]` sections now work correctly

### Added
- Added `github.com/go-viper/encoding/ini` dependency for proper INI file support
- Enhanced debug logging for configuration troubleshooting (with license values redacted for security)

### Changed  
- Improved license error messages to clearly show all three configuration options (config file, environment variable, CLI flag)
- Updated error messages to display actual config file path for better user guidance

## [0.1.6] - 2026-01-16

### Fixed
- Removed unused `buildLicensedPath` function from intelligence API client

### Added
- README documentation for resource control options (ChunkSize, ContentLimit, MatchTimeout, AllowIOErrors, FollowSymlinks)
- README documentation for low-priority scanning with `nice` and `ionice`
- Performance tips section in README

### Changed
- Code formatting fixes via `go fmt`

## [0.1.5] - 2026-01-16

### Fixed
- Fixed vulnerability API endpoint (was incorrectly using `/{license}/scanner`, now uses `/vulnerabilities/scanner`)
- Fixed remediation API call - `get_wp_file_content` now uses POST with form data in body (matching Python CLI behavior)
- Added proper validation for required fields in remediation (WordPress version, plugin/theme name and version)

### Added
- Added `GetDefaultLogger()` function to logging package for sharing logger instances
- Added debug logging for remediation showing detected WordPress site, version, and local path
- Comprehensive README documentation including:
  - Detailed usage examples for malware-scan, vuln-scan, and remediate commands
  - Complete flag reference tables
  - Output format examples (human, CSV, JSON)
  - Remediation limitations table
  - Advanced examples (find piping, cron jobs, automated remediation)
  - Feature comparison with Python CLI

### Changed
- Improved error messages for remediation failures (now indicates specific missing fields)

## [0.1.4] - 2026-01-15

### Changed
- Updated Go dependencies:
  - `github.com/fatih/color` v1.16.0 → v1.18.0
  - `github.com/spf13/cobra` v1.8.0 → v1.10.2
  - `github.com/spf13/viper` v1.18.2 → v1.21.0
- Updated GitHub Actions:
  - `actions/checkout` v4.2.2 → v6.0.1
  - `actions/setup-go` v5.2.0 → v6.2.0
  - `ossf/scorecard-action` v2.4.0 → v2.4.3
  - `github/codeql-action` v3.28.x → v4.31.10

## [0.1.3] - 2026-01-15

### Fixed
- Comprehensive golangci-lint fixes (165 issues resolved)
  - **errcheck**: Added proper error handling for ignored return values
  - **errorlint**: Changed type assertions to `errors.As()`, comparisons to `errors.Is()`
  - **goconst**: Extracted repeated format strings to constants
  - **gosec**: Fixed file permissions (0600/0750), added nolint directives for intentional operations
  - **musttag**: Added json tags to `CommonString` and `Signature` structs
  - **nilnil**: Created sentinel errors for license management
  - **revive**: Fixed stuttering type names, added comments to exported constants, fixed unused parameters
  - **staticcheck**: Applied De Morgan's law simplification
  - **wrapcheck**: Wrapped all external package errors with context

### Changed
- Renamed types to avoid stuttering:
  - `cache.CacheEntry` → `cache.Entry`
  - `scanner.ScannerOption` → `scanner.Option`
  - `api.APIError` → `api.NOC1Error`

## [0.1.2] - 2026-01-14

### Added
- Comprehensive test suite
  - Unit tests for cache package
  - Unit tests for intel package (signatures, vulnerabilities)
  - Unit tests for scanner package (malware, matcher, filter)
  - Unit tests for wordpress package (site detection, plugins, themes)

## [0.1.1] - 2026-01-13

### Added
- Initial project structure and implementation
- Malware scanning with PCRE-compatible regex (regexp2)
- Vulnerability scanning for WordPress core, plugins, and themes
- NOC1 API client for signature fetching
- Intelligence API client for vulnerability data
- File-based caching system
- WordPress site detection and parsing
- CLI commands: malware-scan, vuln-scan, remediate, configure, version
- Multiple output formats: human, csv, tsv, json

## [0.1.0] - 2026-01-12

### Added
- Initial project scaffolding
- Go module initialization
- Basic CLI framework using Cobra
- Configuration system with Viper
- Logging infrastructure
