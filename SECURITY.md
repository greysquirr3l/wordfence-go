# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email your findings to the project maintainers
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 7 days
- **Credit**: We will credit you in the release notes (unless you prefer anonymity)

## Security Considerations

### License Key Handling

- License keys should be stored securely and not committed to version control
- Use environment variables (`WORDFENCE_CLI_LICENSE`) or secure configuration files
- The CLI reads license keys with restricted file permissions (0600)

### File Operations

- The scanner only reads files; it does not modify them unless using `remediate`
- The `remediate` command creates backups before modifying files
- Cache files are stored with restricted permissions (0600)
- Cache directories are created with restricted permissions (0750)

### Network Security

- All API communications use HTTPS
- API endpoints are pinned to Wordfence infrastructure
- No third-party telemetry or data collection

### Build Security

- Static binaries with no external dependencies
- No CGO required (pure Go)
- Reproducible builds via Makefile

## Dependency Security

We regularly audit dependencies for known vulnerabilities. The project uses minimal dependencies:

- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration
- `github.com/dlclark/regexp2` - PCRE-compatible regex
- `github.com/fatih/color` - Terminal colors

Run `go mod verify` to verify dependency integrity.

## Security Best Practices for Users

1. **Keep the CLI updated** to the latest version
2. **Protect your license key** - treat it like a password
3. **Review scan results** before taking remediation actions
4. **Use restricted permissions** for configuration files
5. **Run with least privilege** - the scanner only needs read access to files being scanned
