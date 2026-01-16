# Wordfence CLI (Go)

A Go port of the [Wordfence CLI](https://github.com/wordfence/wordfence-cli) for static binary deployment on legacy Linux systems.

## Features

- **Static binary** - No dependencies, runs on old Linux systems (glibc 2.17+)
- **Malware scanning** - PCRE-compatible signature matching
- **Vulnerability scanning** - WordPress core, plugin, and theme CVE detection
- **Embedded rules** - Optionally compile signatures into the binary for airgapped environments

## Installation

### Pre-built binaries

Download from [Releases](../../releases).

### Build from source

```bash
# Current platform
make build

# Cross-compile for Linux x86_64 (static)
make build-linux-amd64

# Cross-compile for Linux ARM64 (static)
make build-linux-arm64
```

### Build with embedded rules

For airgapped environments, you can bake the malware signatures directly into the binary:

```bash
# Fetch rules (requires valid license key)
make fetch-rules LICENSE_KEY=your_license_key

# Build with embedded rules
make build-embedded-linux-amd64
```

## Usage

```bash
# Validate license
wordfence configure --license /path/to/license.txt

# Scan for malware
wordfence malware-scan /var/www/html

# Scan for vulnerabilities
wordfence vuln-scan /var/www/html

# JSON output
wordfence malware-scan --output-format json /var/www/html
```

## Configuration

Configuration can be set via:
1. Command-line flags
2. Environment variables (`WORDFENCE_*`)
3. INI config file (`~/.config/wordfence/wordfence.ini`)

```ini
# ~/.config/wordfence/wordfence.ini
[DEFAULT]
license = /path/to/license.txt
cache-directory = /tmp/wordfence-cache
workers = 8
```

## Requirements

- Valid Wordfence CLI license key
- Go 1.21+ (for building)

## License

This is an unofficial port. See [Wordfence CLI](https://github.com/wordfence/wordfence-cli) for the original project.
