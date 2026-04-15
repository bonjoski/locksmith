# Locksmith 🔐

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bonjoski/locksmith/badge)](https://scorecard.dev/viewer/?uri=github.com/bonjoski/locksmith)
[![Go Report Card](https://goreportcard.com/badge/github.com/bonjoski/locksmith)](https://goreportcard.com/report/github.com/bonjoski/locksmith)
[![CI](https://github.com/bonjoski/locksmith/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/locksmith/actions/workflows/ci.yml)
[![Check](https://github.com/bonjoski/locksmith/actions/workflows/check.yml/badge.svg)](https://github.com/bonjoski/locksmith/actions/workflows/check.yml)
[![Homebrew](https://img.shields.io/github/v/release/bonjoski/locksmith?label=homebrew&color=orange)](https://github.com/bonjoski/locksmith)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/12451/badge)](https://bestpractices.coreinfrastructure.org/projects/12451)
[![GitHub release](https://img.shields.io/github/v/release/bonjoski/locksmith)](https://github.com/bonjoski/locksmith/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-blue)](https://github.com/bonjoski/locksmith)

**Locksmith** is a secure, biometric-protected keychain vault for macOS, Windows, and Linux. It allows you to store keys, tokens, and passwords in the native system keychain, requiring biometric authentication (Touch ID on macOS, Windows Hello on Windows, Polkit/Secret Service on Linux) for access.

## Features

- **Biometric Security**: Leverages macOS `LocalAuthentication`, **Windows Hello**, and **Linux Polkit** for biometric and interactive protection.
- **MCP Server**: Built-in support for the **Model Context Protocol**, allowing AI agents (like Claude or Cursor) to securely access secrets via biometric gates.
- **Keychain Integration**: Stores secrets in the secure macOS Keychain Services, **Windows Credential Manager**, and the **Linux Secret Service DBus**.
- **Disk Caching**: Optional encrypted disk cache for fast re-access with configurable TTL.
- **CLI & Library**: Use it as a standalone command-line tool or import it as a Go package.
- **Auto-Provisioning**: Built-in `Makefile` that automatically installs its own security and quality tools.

## Installation

### Homebrew (macOS)
The **preferred method** for installing Locksmith on macOS. This ensures you receive a pre-signed binary that is compatible with macOS security policies:

```bash
brew tap bonjoski/locksmith
brew install locksmith
```

#### Troubleshooting `Permission denied (publickey)`
If you encounter a `publickey` error despite the repository being public, your local Git config is likely forcing SSH for all GitHub connections. You can bypass this for just this command without changing your global configuration:
```bash
GIT_CONFIG_GLOBAL=/dev/null brew tap bonjoski/locksmith
```

## Library Usage (Go Module)

> [!WARNING]
> While Locksmith can be used as a Go module, the **Homebrew CLI** is the recommended way to interact with the vault on macOS. 
> Using it as a library requires your host application to have specific signing entitlements to access the macOS Keychain, which can lead to `Permission Denied` errors if not handled correctly.

The `locksmith` library is **read-only** by default...




### macOS Prerequisites
- macOS with Touch ID or Apple Watch support.
- Go 1.25.4.
- Xcode Command Line Tools (`xcode-select --install`).
- An Apple Developer ID is recommended for persistent trust, but ad-hoc signing (`-`) is supported for local development.

### Windows Prerequisites
- Windows 10/11 with Windows Hello support.
- Go 1.25.4.

### Build from Source
```bash
git clone https://github.com/bonjoski/locksmith.git
cd locksmith
make build
make sign
# Binaries are now located in bin/
```

## Usage

### Storing a Secret
```bash
bin/locksmith add my-service my-password --expires 30d
```

### Retrieving a Secret
```bash
bin/locksmith get my-service
```

### Listing Keys
```bash
bin/locksmith list
```

## AI & Model Context Protocol (MCP)

Locksmith includes a built-in MCP server that allows AI agents to securely interact with your keychain. All tool calls are protected by the same biometric gates as the CLI.

### Configuration

Add Locksmith to your `claude_desktop_config.json` or Cursor MCP settings:

```json
{
  "mcpServers": {
    "locksmith": {
      "command": "/absolute/path/to/locksmith/bin/locksmith",
      "args": ["mcp"]
    }
  }
}
```

### Supported Tools
- `locksmith_get_secret`: Retrieve a secret (requires Touch ID/biometrics).
- `locksmith_set_secret`: Store a new secret (defaults to 90-day expiry).
- `locksmith_list_secrets`: List names of stored secrets.
- `locksmith_delete_secret`: Remove a secret.

> [!IMPORTANT]
> When an AI agent requests a secret, you will be prompted for biometrics on your hardware. The AI cannot bypass this gate.

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
auth:
  require_biometrics: true  # Enforce Touch ID / Windows Hello
  prompt_message: "Authenticate to access Locksmith secret '%s'" # Optional custom prompt 

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
# Run all quality and security checks
make check

# Run manual biometric regression tests (macOS)
make test-manual

# View all available commands
make help
```

## Security Features

Locksmith implements defense-in-depth security:

- **Hardware-backed security**: Biometric authentication is enforced by the macOS Secure Enclave and Windows TPM.
- **Biometric protection**: Touch ID/Face ID, Apple Watch, and Windows Hello required for sensitive operations.
- **Memory zeroing**: Secrets cleared from memory immediately after use
- **SLSA provenance**: Releases include cryptographic attestations
- **Continuous Fuzzing**: Daily fuzz testing of critical parsing logic
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

## AI Ready 🤖
This repository is optimized for AI-assisted development.
- **Rules & Guidelines**: See [.cursorrules](file:///.cursorrules) and [.memory/guidelines.md](file:///.memory/guidelines.md).
- **Architecture**: See [.memory/architecture.md](file:///.memory/architecture.md) for Mermaid diagrams and data flow.
- **Tech Stack**: Details on libraries and platform bridges in [.memory/tech-stack.md](file:///.memory/tech-stack.md).
