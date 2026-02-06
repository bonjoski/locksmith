# Locksmith 🔐

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

## Development

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
