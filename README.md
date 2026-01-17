# Wordfence CLI (Go)

Wordfence CLI is a high-performance, multi-threaded security scanner that quickly scans filesystems to detect PHP/other
malware and WordPress vulnerabilities. This is a Go port of the [official Python Wordfence CLI](https://github.com/wordfence/wordfence-cli) designed for static binary
deployment on legacy Linux systems.

## Features

- **Static binary** - No dependencies, single executable runs on old Linux systems (glibc 2.17+)
- **Malware scanning** - PCRE-compatible signature matching with 6,900+ malware signatures
- **Vulnerability scanning** - WordPress core, plugin, and theme CVE detection
- **File remediation** - Automatically restore infected WordPress files to clean versions
- **Embedded rules** - Optionally compile signatures into the binary for airgapped environments
- **Multiple output formats** - Human-readable, CSV, TSV, and JSON output

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

# Build all platforms
make build-all
```

### Build with embedded rules

For airgapped environments, you can bake the malware signatures directly into the binary:

```bash
# Fetch rules (requires valid license key)
make fetch-rules LICENSE_KEY=your_license_key

# Build with embedded rules
make build-embedded-linux-amd64
```

## Requirements

- Valid Wordfence CLI license key
- Go 1.21+ (for building from source)

### Obtaining a license

Visit [https://www.wordfence.com/products/wordfence-cli/](https://www.wordfence.com/products/wordfence-cli/) to obtain a license to download the signature set.

## Usage

### Basic Commands

```bash
# Show help
wordfence --help

# Show version
wordfence version

# Configure license
wordfence configure --license YOUR_LICENSE_KEY
```

### Malware Scanning

Recursively scan directories for malware:

```bash
# Scan a directory for malware
wordfence malware-scan /var/www

# Scan multiple directories
wordfence malware-scan /var/www/site1 /var/www/site2

# Output results to CSV
wordfence malware-scan --output-format csv --output results.csv /var/www

# Output results as JSON
wordfence malware-scan --output-format json /var/www

# Scan all file types (not just PHP/HTML/JS)
wordfence malware-scan --include-all-files /var/www

# Use multiple workers for faster scanning
wordfence malware-scan --workers 8 /var/www

# Low-resource scan (reduced workers, delay between files)
wordfence malware-scan --workers 1 --scan-delay 50 /var/www

# Use a performance profile (recommended for production)
wordfence malware-scan --profile gentle /var/www
```

#### Performance Profiles

For easy resource management, use predefined performance profiles:

| Profile | Description | Best For |
| --------- | ------------- | ---------- |
| `gentle` | Minimal resource usage, very slow | Shared hosting, production servers under load |
| `balanced` | Moderate speed and resources | General production use |
| `aggressive` | Maximum speed, high resource usage | Dedicated servers, off-peak scanning |
| `adaptive` | Dynamically adjusts based on system load | Servers with variable load |

```bash
# Production-safe scanning
wordfence malware-scan --profile gentle /var/www

# Default balanced scanning
wordfence malware-scan --profile balanced /var/www

# Fast scanning on dedicated servers
wordfence malware-scan --profile aggressive /var/www

# Adaptive scanning (auto-throttles under load)
wordfence malware-scan --profile adaptive /var/www

# Profile with overrides
wordfence malware-scan --profile balanced --workers 4 /var/www
```

**Profile Settings:**

| Setting | Gentle | Balanced | Aggressive |
| --------- | -------- | ---------- | ------------ |
| Workers | 1 | NumCPU/2 | NumCPU |
| Scan Delay | 100ms | 25ms | 0 |
| Memory Limit | 256MB | 512MB | Unlimited |
| Max Load Avg | 2.0 | NumCPU×0.75 | Unlimited |
| I/O Limit | 5 MB/s | 20 MB/s | Unlimited |
| Batch Size | 50 files | 100 files | None |

#### Resource Control Options

The malware scanner provides several options to control resource utilization, particularly useful for production servers:

| Flag | Description | Default |
| ------ | ------------- | --------- |
| `--workers N` | Number of concurrent scanning workers | NumCPU |
| `--scan-delay MS` | Delay in milliseconds between files (reduces CPU/IO pressure) | 0 |
| `--chunk-size KB` | Memory buffer size for reading files | 1024 KB |
| `--max-file-size MB` | Maximum file size to scan (0 = unlimited) | 0 |
| `--match-timeout SEC` | Timeout for each regex match | 1 sec |
| `--allow-io-errors` | Continue on file read errors | false |
| `--follow-symlinks` | Follow symbolic links | false |

**Advanced Resource Control:**

| Flag | Description | Default |
| ------ | ------------- | --------- |
| `--memory-limit MB` | Pause scanning when memory exceeds limit | Unlimited |
| `--io-rate-limit MB/s` | Maximum disk read speed | Unlimited |
| `--batch-size N` | Scan N files then pause (use with `--batch-pause`) | Disabled |
| `--batch-pause MS` | Pause duration after each batch | Disabled |
| `--max-load FLOAT` | Pause when system load exceeds value (Unix only) | Unlimited |

**Examples for resource-constrained environments:**

```bash
# Gentle scan: single worker with 50ms delay between files
wordfence malware-scan --workers 1 --scan-delay 50 /var/www

# Memory-efficient: smaller chunk size
wordfence malware-scan --chunk-size 256 /var/www

# Skip large files (over 10MB)
wordfence malware-scan --max-file-size 10 /var/www

# Combined: production-safe settings
wordfence malware-scan --workers 2 --scan-delay 25 --max-file-size 50 /var/www

# Advanced: memory and I/O limiting
wordfence malware-scan --memory-limit 256 --io-rate-limit 10 /var/www

# Advanced: batch processing with pauses
wordfence malware-scan --batch-size 100 --batch-pause 1000 /var/www

# Advanced: load-aware scanning (Unix)
wordfence malware-scan --max-load 4.0 /var/www
```

#### Pipeline Mode (Advanced)

The `--pipeline` flag enables an advanced scanning architecture with additional features:

| Feature | Description |
| ------- | ----------- |
| **Staged Pipeline** | Files flow through: discover → filter → read → match → report |
| **Buffer Pooling** | Reuses memory buffers (tiered: 4KB/64KB/1MB) to reduce allocations |
| **Token Bucket Rate Limiting** | Smooth I/O throttling with burst support |
| **Circuit Breaker** | Prevents cascading failures from I/O errors |
| **Idempotency** | Content hashing detects duplicate files |
| **Graceful Shutdown** | Proper cleanup on cancellation |

```bash
# Use pipeline scanner with I/O rate limiting
wordfence malware-scan --pipeline --io-rate-limit 10 /var/www

# Pipeline with all advanced features
wordfence malware-scan --pipeline --workers 4 --max-file-size 50 /var/www
```

**Pipeline output includes additional statistics:**
```
Pipeline scan complete:
  Stage: Discovered: 1542 → Filtered: 876 → Read: 876 → Matched: 876 → Reported: 876
  Files with matches: 3
  Files skipped: 666
  Duplicates skipped: 12
  Total matches: 5
  Bytes scanned: 42 MB
  Duration: 12.345s
  Buffer pool hit rate: 87.3%
```

### Vulnerability Scanning

Scan WordPress installations for known vulnerabilities:

```bash
# Scan a WordPress installation
wordfence vuln-scan /var/www/wordpress

# Scan multiple installations
wordfence vuln-scan /var/www/site1 /var/www/site2

# Output results to CSV
wordfence vuln-scan --output-format csv --output vulns.csv /var/www/wordpress

# Include informational vulnerabilities
wordfence vuln-scan --informational /var/www/wordpress
```

### File Remediation

Automatically restore infected WordPress files to their original clean versions:

```bash
# Remediate a single file
wordfence remediate /var/www/wordpress/wp-includes/infected.php

# Remediate an entire WordPress installation
wordfence remediate /var/www/wordpress

# Preview changes without modifying files (dry run)
wordfence remediate --dry-run /var/www/wordpress

# Pipe malware scan results directly to remediation
wordfence malware-scan --output-format csv /var/www/wordpress | \
  awk -F, 'NR>1 {print $1}' | \
  wordfence remediate --read-stdin
```

#### Remediation Limitations

| File Type | Can Remediate? | Notes |
| ----------- | --------------- | ------- |
| WordPress Core | ✅ Yes | Files in wp-admin/, wp-includes/ |
| Known Plugins | ✅ Yes | Plugins in wordpress.org repo |
| Known Themes | ✅ Yes | Themes in wordpress.org repo |
| Custom Code | ❌ No | Must review manually |
| Premium/Paid Plugins | ❌ No | Not in public repo |
| Modified Files | ⚠️ Caution | Customizations will be lost |

**Note:** Remediation only works for known WordPress files (core, plugins from wordpress.org, themes from wordpress.org).
Custom code cannot be automatically remediated.

### Advanced Examples

#### Piping files from `find` to Wordfence CLI

Scan files modified in the last hour:

```bash
find /var/www/ -cmin -60 -type f | wordfence malware-scan --read-stdin
```

#### Running in a cron job

Daily malware scan with results logged:

```bash
0 0 * * * /usr/bin/flock -w 0 /tmp/wordfence.lock /usr/local/bin/wordfence malware-scan --output-format csv --output /var/log/wordfence/scan.csv /var/www 2>&1 >> /var/log/wordfence/scan.log
```

#### Automated detection and remediation

```bash
wordfence malware-scan --output-format csv /var/www/wordpress | \
  awk -F, 'NR>1 {print $1}' | \
  wordfence remediate --read-stdin
```

#### Low-priority scanning on production servers

Use `nice` and `ionice` to minimize impact on server performance:

```bash
# Lower CPU priority (nice value 10)
nice -n 10 wordfence malware-scan --license "$WORDFENCE_CLI_LICENSE" /var/www

# Lowest CPU priority (nice value 19)
nice -n 19 wordfence malware-scan --license "$WORDFENCE_CLI_LICENSE" /var/www

# Combined CPU and I/O priority limiting (recommended for production)
ionice -c 2 -n 7 nice -n 10 wordfence malware-scan --workers 2 --license "$WORDFENCE_CLI_LICENSE" /var/www
```

**Nice values:** `-20` (highest priority, needs root) to `19` (lowest/most polite). Default is `0`.

**ionice classes:**
- `-c 1` = Real-time (needs root)
- `-c 2` = Best-effort (default), with `-n 0-7` priority (7 = lowest)
- `-c 3` = Idle (only runs when no other I/O)

**Production cron example with resource limits:**

```bash
0 2 * * * ionice -c 2 -n 7 nice -n 10 /usr/bin/flock -w 0 /tmp/wordfence.lock /usr/local/bin/wordfence malware-scan --workers 2 --output-format csv --output /var/log/wordfence/scan.csv /var/www 2>&1 >> /var/log/wordfence/scan.log
```

## Configuration

Configuration can be set via:

1. **Command-line flags** (highest priority)
2. **Environment variables** (`WORDFENCE_CLI_LICENSE`, etc.)
3. **INI config file** (`~/.config/wordfence/wordfence-cli.ini`)

### Configuration File

```ini
# ~/.config/wordfence/wordfence-cli.ini
[DEFAULT]
license = YOUR_LICENSE_KEY
cache-directory = ~/.cache/wordfence
workers = 8
verbose = on
```

### Global Flags

| Flag | Description |
| ------ | ------------- |
| `--license` | Wordfence CLI license key |
| `--config` | Path to configuration file |
| `--cache-dir` | Directory for cache files |
| `--no-cache` | Disable caching |
| `--verbose` | Enable verbose output |
| `--debug` | Enable debug output |
| `--quiet` | Suppress non-error output |
| `--no-color` | Disable colored output |

### Malware Scan Flags

| Flag | Description | Default |
| ------ | ------------- | ------- |
| `--output`, `-o` | Output file path | stdout |
| `--output-format` | Output format: `human`, `csv`, `tsv`, `json` | `human` |
| `--workers`, `-w` | Number of worker goroutines | NumCPU |
| `--include-all-files` | Scan all files, not just PHP/HTML/JS | false |
| `--read-stdin` | Read file paths from stdin | false |
| `--include-files` | Additional filenames to include | |
| `--include-pattern` | Regex patterns for files to include | |
| `--exclude-files` | Filenames to exclude | |
| `--exclude-pattern` | Regex patterns to exclude | |

### Resource Control (Internal Defaults)

These options control resource usage during scanning. They are currently set internally but can be adjusted in the source code:

| Option | Description | Default |
| ------ | ------------- | ------- |
| `ChunkSize` | Memory buffer size for reading files | 1 MB |
| `ContentLimit` | Maximum file content to scan (0 = unlimited) | No limit |
| `MatchTimeout` | Timeout for each regex pattern match | 1 second |
| `AllowIOErrors` | Continue scanning on file read errors | false |
| `FollowSymlinks` | Follow symbolic links during scan | false |

**Performance Tips:**

- **Workers**: Set `--workers` to match your CPU cores for optimal performance
- **Large files**: Files are read into memory; very large files may need `ContentLimit`
- **Slow patterns**: Complex regex patterns may timeout; check for `timeouts` in results
- **Network filesystems**: Consider `AllowIOErrors` for unreliable mounts

### Vulnerability Scan Flags

| Flag | Description |
| ------ | ------------- |
| `--output`, `-o` | Output file path |
| `--output-format` | Output format: `human`, `csv`, `tsv`, `json` |
| `--check-core` | Check WordPress core (default: true) |
| `--check-plugins` | Check plugins (default: true) |
| `--check-themes` | Check themes (default: true) |
| `--informational` | Include informational vulnerabilities |

### Remediate Flags

| Flag | Description |
| ------ | ------------- |
| `--output`, `-o` | Output file path |
| `--output-format` | Output format: `human`, `csv`, `tsv`, `json` |
| `--backup` | Backup files before remediation (default: true) |
| `--backup-dir` | Directory for backups |
| `--dry-run` | Preview changes without modifying files |
| `--read-stdin` | Read file paths from stdin |

## Output Formats

### Human (default)

```text
/var/www/html/malware.php
  Rule ID: 12345
  Rule: WP-VCD malware
  Description: This file contains malicious code associated with WP-VCD malware
```

### CSV

```csv
path,rule_id,rule_name,description
/var/www/html/malware.php,12345,WP-VCD malware,This file contains malicious code...
```

### JSON

```json
{
  "path": "/var/www/html/malware.php",
  "matches": [
    {
      "rule_id": 12345,
      "rule_name": "WP-VCD malware",
      "description": "This file contains malicious code..."
    }
  ]
}
```

## Comparison with Python CLI

| Feature | Go CLI | Python CLI |
| --------- | -------- | ------------ |
| Static binary | ✅ | ❌ (requires Python) |
| Dependencies | None | Python 3.8+, libpcre, pip packages |
| Legacy Linux support | ✅ glibc 2.17+ | Limited |
| Embedded signatures | ✅ | ❌ |
| Database scanning | ❌ | ✅ |
| Email reports | ❌ | ✅ |
| Vectorscan support | ❌ | ✅ |

## License

This is an unofficial Go port. See [Wordfence CLI](https://github.com/wordfence/wordfence-cli) for the original project.

The original Wordfence CLI is open source, licensed under GPLv3.
