# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
