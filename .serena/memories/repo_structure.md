# Repository Structure

```
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
│   └── pcre/                    # PCRE-compatible regex wrapper
│       └── pcre.go
├── reference_projects/
│   └── wordfence-cli/           # Original Python implementation (reference)
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── IMPLEMENTATION_PLAN.md
```

## Key Directories

- `cmd/wordfence/`: Main entry point
- `internal/`: Private packages (Go convention)
- `internal/api/`: Wordfence API clients (NOC1, Intelligence)
- `internal/scanner/`: Core scanning logic
- `internal/wordpress/`: WordPress site/plugin/theme detection
- `reference_projects/`: Original Python code for reference
