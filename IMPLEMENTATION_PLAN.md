# Wordfence CLI - Go Implementation Plan

## Overview

This document outlines the plan to convert the Python-based [wordfence-cli](https://github.com/wordfence/wordfence-cli)
to Go, enabling static compilation for deployment to hosts with outdated software stacks.

### Goals

1. **Single static binary** - No runtime dependencies (Python, libpcre, etc.)
2. **Cross-compilation** - Build for linux/amd64 (x86_64) from any platform
3. **Feature parity** - Support core scanning capabilities of the Python CLI
4. **License compatibility** - Work with existing Wordfence CLI license keys

### Non-Goals (Initial Version)

- Vectorscan/Hyperscan integration (use pure Go regex)
- Database scanning (db-scan subcommand) - defer to later phase
- Count-sites subcommand
- Email notifications
- Progress display with ANSI escape sequences
- Multiprocessing (use goroutines instead)

---

## Architecture Overview

```text
wordfence-go/
├── cmd/
│   └── wordfence/
│       └── main.go              # Entry point
├── internal/
│   ├── api/                     # Wordfence API clients
│   │   ├── client.go            # Base HTTP client
│   │   ├── noc1.go              # NOC1 API (signatures, licensing)
│   │   ├── intelligence.go      # WFI API (vulnerabilities)
│   │   └── license.go           # License management
│   ├── cache/                   # Local caching system
│   │   ├── cache.go             # Cache interface
│   │   └── filecache.go         # File-based cache
│   ├── cli/                     # CLI framework
│   │   ├── app.go               # Main application
│   │   ├── config.go            # Configuration handling
│   │   └── output.go            # Output formatting
│   ├── intel/                   # Threat intelligence
│   │   ├── signatures.go        # Malware signatures
│   │   └── vulnerabilities.go   # Vulnerability data
│   ├── scanner/                 # Scanning engine
│   │   ├── malware.go           # Malware scanner
│   │   ├── vuln.go              # Vulnerability scanner
│   │   ├── filter.go            # File filtering
│   │   └── worker.go            # Concurrent workers
│   ├── wordpress/               # WordPress detection
│   │   ├── site.go              # WP site detection
│   │   ├── plugin.go            # Plugin parsing
│   │   ├── theme.go             # Theme parsing
│   │   └── version.go           # Version parsing
│   └── util/                    # Utilities
│       ├── version.go           # Version comparison
│       └── io.go                # I/O helpers
├── pkg/
│   └── pcre/                    # PCRE-compatible regex (pure Go)
│       └── pcre.go
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## Phase 1: Foundation (Week 1)

### 1.1 Project Setup

- [ ] Initialize Go module (`go mod init github.com/nickcampbell/wordfence-go`)
- [ ] Create Makefile with cross-compilation targets
- [ ] Set up basic CLI using `cobra` or `urfave/cli`
- [ ] Implement version command

### 1.2 Configuration System

Map Python config to Go structs:

```go
type GlobalConfig struct {
    LicenseKey      string `yaml:"license" env:"WORDFENCE_CLI_LICENSE"`
    CacheDirectory  string `yaml:"cache-directory" default:"~/.cache/wordfence"`
    CacheEnabled    bool   `yaml:"cache" default:"true"`
    Debug           bool   `yaml:"debug" default:"false"`
    Verbose         bool   `yaml:"verbose" default:"false"`
    Quiet           bool   `yaml:"quiet" default:"false"`
    NoColor         bool   `yaml:"no-color" default:"false"`
}
```

Config sources (priority order):

1. Command-line flags
2. Environment variables (`WORDFENCE_CLI_*`)
3. INI config file (`~/.config/wordfence/wordfence-cli.ini`)
4. Default values

### 1.3 Logging System

- [ ] Implement leveled logging (DEBUG, VERBOSE, INFO, WARNING, ERROR)
- [ ] Support colored output (optional)
- [ ] Support `--quiet` and `--verbose` flags

---

## Phase 2: API Integration (Week 1-2)

### 2.1 Base HTTP Client

```go
type NocClient struct {
    BaseURL    string
    License    *License
    HTTPClient *http.Client
    Timeout    time.Duration
}

func (c *NocClient) Request(action string, params map[string]string) ([]byte, error)
```

### 2.2 NOC1 API Client

Base URL: `https://noc1.wordfence.com/v2.27/`

Endpoints to implement:

| Action | Purpose | Priority |
|--------|---------|----------|
| `ping_api_key` | Validate license | High |
| `get_cli_api_key` | Convert site key to CLI key | Medium |
| `get_patterns` | Fetch malware signatures | High |
| `get_precompiled_patterns` | Fetch pre-compiled signatures | Low |

### 2.3 Intelligence API Client

Base URL: `https://www.wordfence.com/api/intelligence/v2`

Endpoints:

| Endpoint | Purpose | Priority |
|----------|---------|----------|
| `/scanner/...` | Scanner vulnerability feed | High |
| `/production/...` | Production vulnerability feed | Medium |

### 2.4 License Management

```go
type License struct {
    Key  string
    Paid bool
}

func ValidateLicense(key string) (*License, error)
```

---

## Phase 3: Caching System (Week 2)

### 3.1 Cache Interface

```go
type Cache interface {
    Get(key string, maxAge time.Duration) ([]byte, error)
    Put(key string, data []byte) error
    Remove(key string) error
    Purge() error
}
```

### 3.2 File-Based Cache

- Location: `~/.cache/wordfence/` (XDG-compliant)
- Key encoding: Base16 of key string
- File locking for concurrent access
- TTL-based expiration (default: 24 hours)

Cached items:

- `signatures` - Malware signature set
- `vulnerability_index_scanner` - Vulnerability feed
- `pre-compiled-signatures-*` - Pre-compiled patterns (if used)

---

## Phase 4: Malware Signatures (Week 2)

### 4.1 Signature Data Structures

```go
type CommonString struct {
    String       string
    SignatureIDs []int
}

type Signature struct {
    ID           int
    Rule         string      // PCRE pattern
    Name         string
    Description  string
    CommonStrings []int      // Indices into CommonStrings array
}

type SignatureSet struct {
    CommonStrings []CommonString
    Signatures    map[int]*Signature
}
```

### 4.2 Signature Parsing

Parse the `get_patterns` response:

- `rules[]` - Array of signature records
- `commonStrings[]` - Shared strings for optimization
- `signatureUpdateTime` - Timestamp for cache invalidation

### 4.3 PCRE-Compatible Regex

Options:

1. **regexp2** (recommended) - Go port of .NET regex with PCRE-like features
2. **go-pcre** - CGO bindings to libpcre (defeats static binary goal)
3. **Standard regexp** - May not support all PCRE features

```go
import "github.com/dlclark/regexp2"

type Matcher struct {
    regex *regexp2.Regexp
}

func (m *Matcher) Match(content []byte) (bool, string, error)
```

Key PCRE features needed:

- Case-insensitive matching (`(?i)`)
- Multiline mode (`(?m)`)
- Backreferences
- Lookahead/lookbehind assertions

---

## Phase 5: Malware Scanner (Week 3)

### 5.1 File Filter

```go
type FileFilter struct {
    conditions []FilterCondition
}

type FilterCondition struct {
    Test  func(path string) bool
    Allow bool
}
```

Default filters (from Python):

- `.php`, `.php5`, `.phtml` files
- `.html`, `.htm` files
- `.js`, `.svg` files

### 5.2 Scanner Options

```go
type ScanOptions struct {
    Paths              []string
    Workers            int
    ChunkSize          int
    IncludeAllFiles    bool
    IncludeFiles       []string
    IncludePattern     []string
    ExcludeFiles       []string
    ExcludePattern     []string
    IncludeSignatures  []int
    ExcludeSignatures  []int
    ScannedContentLimit int
    AllowIOErrors      bool
    FollowSymlinks     bool
}
```

### 5.3 Scanner Implementation

```go
type Scanner struct {
    signatures *SignatureSet
    filter     *FileFilter
    options    *ScanOptions
    results    chan *ScanResult
}

type ScanResult struct {
    Path        string
    SignatureID int
    MatchedText string
    Error       error
}

func (s *Scanner) ScanFile(path string) []*ScanResult
func (s *Scanner) ScanDirectory(path string) <-chan *ScanResult
```

### 5.4 Concurrent Scanning

Use worker pool pattern:

```go
func (s *Scanner) Scan(ctx context.Context) <-chan *ScanResult {
    jobs := make(chan string, 1000)
    results := make(chan *ScanResult, 100)
    
    // File locator goroutine
    go s.locateFiles(ctx, jobs)
    
    // Worker pool
    var wg sync.WaitGroup
    for i := 0; i < s.options.Workers; i++ {
        wg.Add(1)
        go s.worker(ctx, jobs, results, &wg)
    }
    
    // Close results when done
    go func() {
        wg.Wait()
        close(results)
    }()
    
    return results
}
```

---

## Phase 6: Vulnerability Scanner (Week 3-4)

### 6.1 Vulnerability Data Structures

```go
type SoftwareType string

const (
    SoftwareTypeCore   SoftwareType = "core"
    SoftwareTypePlugin SoftwareType = "plugin"
    SoftwareTypeTheme  SoftwareType = "theme"
)

type VersionRange struct {
    FromVersion   string
    FromInclusive bool
    ToVersion     string
    ToInclusive   bool
}

type Vulnerability struct {
    ID          string
    Title       string
    Description string
    Software    []AffectedSoftware
    CVE         string
    CVSS        *CVSSScore
    Published   time.Time
    References  []string
}

type AffectedSoftware struct {
    Type            SoftwareType
    Slug            string
    Name            string
    AffectedVersions map[string]VersionRange
    Patched         bool
    PatchedVersions []string
}
```

### 6.2 Vulnerability Index

```go
type VulnerabilityIndex struct {
    vulnerabilities map[string]*Vulnerability
    byType          map[SoftwareType]map[string][]*indexEntry
}

type indexEntry struct {
    versionRange *VersionRange
    vulnID       string
}

func (vi *VulnerabilityIndex) GetVulnerabilities(
    softwareType SoftwareType,
    slug string,
    version string,
) []*Vulnerability
```

### 6.3 Version Comparison

Implement PHP-style version comparison:

```go
func CompareVersions(v1, v2 string) int // -1, 0, or 1
func NormalizeVersion(version string) string
```

Handle version formats:

- Standard: `1.2.3`
- With prerelease: `1.2.3-beta1`
- WordPress style: `5.9.1`

---

## Phase 7: WordPress Detection (Week 4)

### 7.1 Site Detection

```go
type WordPressSite struct {
    Path        string
    CorePath    string
    ContentPath string
    Version     string
    Plugins     []*Plugin
    Themes      []*Theme
}

func DetectWordPress(path string) (*WordPressSite, error)
```

Detection criteria:

- `wp-blog-header.php` exists
- `wp-load.php` exists
- `wp-admin/` directory exists
- `wp-includes/` directory exists

### 7.2 Version Detection

Parse `wp-includes/version.php`:

```go
func ParseWordPressVersion(versionFile string) (string, error)
// Extract $wp_version = 'X.Y.Z';
```

### 7.3 Plugin Detection

Parse plugin headers from main PHP file:

```go
type Plugin struct {
    Slug    string
    Name    string
    Version string
    Path    string
}

func (pl *PluginLoader) LoadAll(pluginsDir string) ([]*Plugin, error)
```

Header fields to parse:

- `Plugin Name:`
- `Version:`
- `Author:`

### 7.4 Theme Detection

Parse `style.css` headers:

```go
type Theme struct {
    Slug    string
    Name    string
    Version string
    Path    string
}

func (tl *ThemeLoader) LoadAll(themesDir string) ([]*Theme, error)
```

Header fields:

- `Theme Name:`
- `Version:`

---

## Phase 8: Output Formatting (Week 4)

### 8.1 Report Formats

```go
type OutputFormat string

const (
    FormatHuman       OutputFormat = "human"
    FormatCSV         OutputFormat = "csv"
    FormatTSV         OutputFormat = "tsv"
    FormatJSON        OutputFormat = "json"
    FormatNullDelim   OutputFormat = "null-delimited"
    FormatLineDelim   OutputFormat = "line-delimited"
)
```

### 8.2 Malware Scan Output

Columns:

- `filename` - Path to matched file
- `signature_id` - Matched signature ID
- `signature_name` - Human-readable name
- `signature_description` - Description
- `matched_text` - Text that matched (optional)

### 8.3 Vulnerability Scan Output

Columns:

- `software_type` - core/plugin/theme
- `slug` - Software identifier
- `version` - Installed version
- `vulnerability_id` - UUID
- `title` - Vulnerability title
- `link` - Wordfence URL
- `cve` - CVE identifier (if available)

---

## Phase 9: CLI Commands (Week 5)

### 9.1 Command Structure

```text
wordfence-go [global options] <command> [command options] [arguments...]

Commands:
  malware-scan    Scan files for malware
  vuln-scan       Scan WordPress for vulnerabilities
  remediate       Remediate infected files
  configure       Configure the CLI
  version         Display version information
  help            Display help
```

### 9.2 Global Options

| Flag | Env Var | Description |
| ------ | --------- | ------------- |
| `--license` | `WORDFENCE_CLI_LICENSE` | License key |
| `--config` | `WORDFENCE_CLI_CONFIG_FILE` | Config file path |
| `--cache-dir` | `WORDFENCE_CLI_CACHE_DIR` | Cache directory |
| `--no-cache` | | Disable caching |
| `--debug` | | Enable debug output |
| `--verbose` | | Verbose output |
| `--quiet` | | Suppress non-error output |
| `--no-color` | `NO_COLOR` | Disable colored output |

### 9.3 malware-scan Command

```text
wordfence-go malware-scan [options] <paths...>

Options:
  --output, -o           Output file (default: stdout)
  --output-format        Output format: csv, tsv, json, human (default: human)
  --output-columns       Columns to include
  --workers, -w          Number of worker goroutines (default: NumCPU)
  --include-all-files    Scan all files, not just PHP/HTML/JS
  --include-files        Additional filenames to include
  --include-pattern      Regex patterns for files to include
  --exclude-files        Filenames to exclude
  --exclude-pattern      Regex patterns to exclude
  --include-signatures   Only use these signature IDs
  --exclude-signatures   Exclude these signature IDs
  --read-stdin           Read paths from stdin
```

### 9.4 vuln-scan Command

```text
wordfence-go vuln-scan [options] <paths...>

Options:
  --output, -o           Output file (default: stdout)
  --output-format        Output format: csv, tsv, json, human
  --output-columns       Columns to include
  --include-vuln-ids     Only report these vulnerability IDs
  --exclude-vuln-ids     Exclude these vulnerability IDs
  --informational        Include informational vulnerabilities
  --check-core           Check WordPress core (default: true)
  --check-plugins        Check plugins (default: true)
  --check-themes         Check themes (default: true)
```

### 9.5 remediate Command

```text
wordfence-go remediate [options] <paths...>

Options:
  --output, -o           Output file
  --output-format        Output format
  --read-stdin           Read paths from stdin
```

---

## Phase 10: Testing & Quality (Week 5)

### 10.1 Unit Tests

- API client mocking
- Signature matching
- Version comparison
- WordPress detection
- File filtering

### 10.2 Integration Tests

- End-to-end malware scan
- End-to-end vuln scan
- Cache behavior
- License validation

### 10.3 Test Data

Create fixtures:

- Sample PHP files with known malware signatures
- Mock WordPress installations
- Plugin/theme headers

---

## Phase 11: Build & Distribution (Week 5)

### 11.1 Makefile Targets

```makefile
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: build
build:
 go build $(LDFLAGS) -o bin/wordfence ./cmd/wordfence

.PHONY: build-linux-amd64
build-linux-amd64:
 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) \
  -o bin/wordfence-linux-amd64 ./cmd/wordfence

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

.PHONY: test
test:
 go test -race -cover ./...

.PHONY: lint
lint:
 golangci-lint run
```

### 11.2 Static Binary Requirements

- `CGO_ENABLED=0` for static linking
- Use pure Go dependencies (no CGO)
- Link flags: `-s -w` to strip debug info

### 11.3 Binary Size Optimization

Expected size: ~15-25 MB (with embedded regex patterns)

Optimization options:

- `upx` compression (reduces to ~5-8 MB)
- Strip symbols
- Exclude debug info

---

## Dependencies

### Required Go Packages

| Package | Purpose | License |
| --------- | --------- | --------- |
| `github.com/spf13/cobra` | CLI framework | Apache 2.0 |
| `github.com/spf13/viper` | Configuration | MIT |
| `github.com/dlclark/regexp2` | PCRE-compatible regex | MIT |
| `github.com/fatih/color` | Colored output | MIT |
| `github.com/schollz/progressbar/v3` | Progress bars | MIT |
| `gopkg.in/ini.v1` | INI file parsing | Apache 2.0 |

### Optional Packages

| Package | Purpose | License |
| --------- | --------- | --------- |
| `github.com/hashicorp/go-retryablehttp` | HTTP retry logic | MPL 2.0 |
| `go.uber.org/zap` | Structured logging | MIT |

---

## Risk Assessment

### High Risk

| Risk | Mitigation |
| ------ | ------------ |
| PCRE regex compatibility | Use regexp2, test extensively |
| API changes | Version-pin API endpoints |
| Signature format changes | Implement format versioning |

### Medium Risk

| Risk | Mitigation |
| ------ | ------------ |
| Performance regression | Benchmark against Python version |
| Missing edge cases | Port Python test cases |
| WordPress detection accuracy | Test with varied WP installations |

### Low Risk

| Risk | Mitigation |
|------|------------|
| Build/deploy complexity | Simple static binary |
| License compatibility | Same GPLv3 license |

---

## Timeline Summary

| Week | Phase | Deliverables |
| ------ | ------- | -------------- |
| 1 | Foundation + API | CLI skeleton, config, NOC1 client |
| 2 | Cache + Signatures | File cache, signature parsing, regex engine |
| 3 | Malware Scanner | File scanning, concurrent workers |
| 4 | Vuln Scanner + WP | WordPress detection, vulnerability matching |
| 5 | Polish | Output formats, testing, documentation |

---

## Success Criteria

1. ✅ Single static binary < 30 MB
2. ✅ Runs on RHEL 6+ / Ubuntu 14.04+ without dependencies
3. ✅ `malware-scan` detects same threats as Python version
4. ✅ `vuln-scan` detects same vulnerabilities as Python version
5. ✅ Works with existing Wordfence CLI license
6. ✅ Cross-compile from macOS to Linux

---

## Future Enhancements (Post-MVP)

1. **Database scanning** - MySQL connectivity via pure Go driver
2. **Vectorscan integration** - Optional CGO build for performance
3. **Email notifications** - SMTP support
4. **Auto-update** - Self-update capability
5. **Plugin architecture** - Custom signature sources
6. **REST API mode** - Run as HTTP server for remote scanning

---

## References

- [Wordfence CLI Documentation](https://github.com/wordfence/wordfence-cli/tree/main/docs)
- [Wordfence CLI Source](https://github.com/wordfence/wordfence-cli)
- [regexp2 - PCRE-compatible Go regex](https://github.com/dlclark/regexp2)
- [Cobra CLI Framework](https://github.com/spf13/cobra)
