# Technical Stack: Locksmith 🔐

## Language & Tools

- **Language**: Go (v1.25.4)
- **Framework**: `cobra` (CLI)
- **Platform Support**: macOS, Windows, Linux
- **Security Validation**: `golangci-lint`, `govulncheck`, `gosec`, `gitleaks`, `semgrep`.
- **Environment**: Scripts and automation require a Bash-compatible shell (standard on macOS/Linux).

## Core Libraries

- **`github.com/spf13/cobra`**: CLI command structure.
- **`github.com/danieljoos/wincred`**: Windows Credential Manager integration.
- **`github.com/julian-bruyers/winhello-go`**: Windows Hello biometric authentication.
- **`github.com/zalando/go-keyring`**: Cross-platform library for secret storage (used as primary backend).
- **`golang.org/x/sys`**: Low-level platform-specific system calls (especially for macOS `LocalAuthentication`).
- **`gopkg.in/yaml.v3`**: Configuration file parsing (`~/.locksmith/config.yml`).

## Architecture

- **[Detailed Architecture Diagram](file:///.memory/architecture.md)**: Visual overview of components and data flow.
- **`cmd/`**: CLI entry points for the main app and Summon provider.
- **`pkg/locksmith/`**: Core logic for secret retrieval, listing, and metadata handling.
- **`pkg/native/`**: Platform-specific implementations of secret storage and biometrics.
- **Admin vs. Standard**: Write/Delete operations are protected by the `locksmith_admin` build tag to prevent accidental modifications when importing as a library.

## Data Models

- **`Secret`**: JSON-serialized object in the keychain containing value, creation date, and expiration.
- **`SecretMetadata`**: Light-weight representation for listing secrets without decoding the actual sensitive value.

## Biometric Integration Patterns

- **macOS**: `LocalAuthentication` framework using `LAPolicyDeviceOwnerAuthenticationWithBiometrics`.
- **Windows**: Windows Hello via `winhello-go`.
- **Linux**: Polkit integration for Secret Service access control.
