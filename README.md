# Locksmith 🔐

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bonjoski/locksmith/badge)](https://scorecard.dev/viewer/?uri=github.com/bonjoski/locksmith)
[![Go Report Card](https://goreportcard.com/badge/github.com/bonjoski/locksmith)](https://goreportcard.com/report/github.com/bonjoski/locksmith)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/v/release/bonjoski/locksmith)](https://github.com/bonjoski/locksmith/releases)
[![Platform](https://img.shields.io/badge/platform-macOS-blue)](https://github.com/bonjoski/locksmith)

**Locksmith** is a secure, biometric-protected keychain vault for macOS. It allows you to store keys, tokens, and passwords in the native macOS Keychain, requiring Touch ID (or your system password) for access.

## Features

- **Biometric Security**: Leverages macOS `LocalAuthentication` for Touch ID protection.
- **Keychain Integration**: Stores secrets in the secure macOS Keychain Services.
- **Disk Caching**: Optional encrypted disk cache for fast re-access with configurable TTL.
- **CLI & Library**: Use it as a standalone command-line tool or import it as a Go package.
- **Auto-Provisioning**: Built-in `Makefile` that automatically installs its own security and quality tools.

## Installation

### Prerequisites
- macOS with Touch ID support.
- Go 1.21+ installed.
- Xcode Command Line Tools (`xcode-select --install`).
- An Apple Developer account (for code signing).

### Build from Source
```bash
git clone https://github.com/bonjoski/locksmith.git
cd locksmith
make build
make sign
```

## Usage

### Storing a Secret
```bash
./locksmith add my-service my-password --expires 30d
```

### Retrieving a Secret
```bash
./locksmith get my-service
```

### Listing Keys
```bash
./locksmith list
```

### Summon Integration

Locksmith can be used as a [Summon](https://cyberark.github.io/summon) provider to inject biometric-protected secrets into processes:

#### Installation
```bash
make install-summon
```

#### Usage
Create a `secrets.yml` file:
```yaml
AWS_ACCESS_KEY_ID: !var aws/access-key
AWS_SECRET_ACCESS_KEY: !var aws/secret-key
DATABASE_PASSWORD: !var db/password
```

Run your command with Summon:
```bash
summon --provider locksmith -f secrets.yml <command>
```

**Examples:**
```bash
# Docker with biometric-protected secrets
summon --provider locksmith -f secrets.yml docker run --env-file @SUMMONENVFILE myapp

# Python script with AWS credentials
summon --provider locksmith -f secrets.yml python deploy.py

# Any command that reads environment variables
summon --provider locksmith -f secrets.yml env | grep AWS
```

This provides Touch ID authentication for your DevOps workflows, ensuring secrets are never exposed in plaintext.

## Configuration

Locksmith supports optional configuration via `~/.locksmith/config.yml` for customizing expiration notifications:

```yaml
notifications:
  expiring_threshold: 7d    # Warn when secrets expire within this duration
  method: stderr            # Options: stderr, macos, silent
  show_on_get: true         # Show warnings on 'get' command
  show_on_list: true        # Show status on 'list' command
```

### Expiration Notifications

Locksmith can warn you about expiring or expired secrets:

**Get command with warnings:**
```bash
$ locksmith get aws/key
Warning: Secret 'aws/key' expires in 2 days
AKIAIOSFODNN7EXAMPLE
```

**JSON output:**
```bash
$ locksmith get aws/key --json
{
  "key": "aws/key",
  "value": "AKIAIOSFODNN7EXAMPLE",
  "created_at": "2026-01-01T12:00:00Z",
  "expires_at": "2026-02-15T12:00:00Z",
  "expires_in": "48h0m0s",
  "is_expired": false,
  "is_expiring": true
}
```

**List command with status:**
```bash
$ locksmith list
KEY                            CREATED              EXPIRES              STATUS
------------------------------------------------------------------------------------
aws/access-key                 2026-01-01           2026-02-15           ⚠️  Expiring
db/password                    2026-01-15           2027-01-15           ✓  Valid
api/token                      2025-12-01           2026-01-01           ❌ Expired
```

**Configuration options:**
- `expiring_threshold`: Duration formats: `7d` (days), `2w` (weeks), `1mo` (months), `1y` (years), `24h` (hours)
- `method`: 
  - `stderr` (default): Print warnings to stderr
  - `macos`: Show macOS notification popup
  - `silent`: No notifications (useful for automation)

See [config.example.yml](config.example.yml) for a complete example.

Locksmith includes a comprehensive suite of quality and security checks.

```bash
# Run all checks (lint, security, gosec, gitleaks)
# This will automatically install any missing tools!
make check

# View all available commands
make help
```

## Security Features

Locksmith implements defense-in-depth security:

- **Hardware-backed encryption**: Secrets protected by macOS Secure Enclave
- **Biometric authentication**: Touch ID/Face ID required for all operations
- **Memory zeroing**: Secrets cleared from memory immediately after use
- **SLSA provenance**: Releases include cryptographic attestations
- **OpenSSF Scorecard**: Automated security assessment

### Verifying Releases

All releases include cryptographic attestations. Verify a binary:

```bash
gh attestation verify locksmith-darwin-arm64 --owner bonjoski
```

See [RELEASING.md](RELEASING.md) for details.

## License
Distributed under the [MIT License](LICENSE). See `LICENSE` for more information.

## Security
For security-related issues, please refer to our [Security Policy](SECURITY.md).
