# Wordfence-Go Project Overview

## Purpose

A Go port of the Python-based wordfence-cli tool, designed to produce a single static binary that can be deployed to hosts with outdated software stacks (RHEL 6+, Ubuntu 14.04+) without requiring runtime dependencies.

## Reference Implementation

The `reference_projects/wordfence-cli/` directory contains the original Python implementation which serves as the specification for this Go port.

## Key Features (MVP)

- **malware-scan**: Scan files for malware signatures
- **vuln-scan**: Scan WordPress installations for vulnerabilities  
- **remediate**: Remediate infected files
- **configure**: Configure the CLI
- **version**: Display version information

## Tech Stack

- **Language**: Go 1.21+
- **CLI Framework**: github.com/spf13/cobra
- **Configuration**: github.com/spf13/viper
- **Regex Engine**: github.com/dlclark/regexp2 (PCRE-compatible, pure Go)
- **Build**: Makefile with CGO_ENABLED=0 for static binaries

## API Endpoints

- NOC1 API: `https://noc1.wordfence.com/v2.27/` (signatures, licensing)
- Intelligence API: `https://www.wordfence.com/api/intelligence/v2` (vulnerabilities)

## Non-Goals (Initial Version)

- Vectorscan/Hyperscan integration
- Database scanning (db-scan)
- Count-sites subcommand
- Email notifications
