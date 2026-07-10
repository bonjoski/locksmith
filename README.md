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
[![Summon Provider](https://img.shields.io/badge/Integration-Summon-005571.svg)](https://cyberark.github.io/summon)

**Locksmith** is a secure, biometric-protected keychain vault for macOS, Windows, and Linux. It allows you to store keys, tokens, and passwords in the native system keychain, requiring biometric authentication (Touch ID on macOS, Windows Hello on Windows, Polkit/Secret Service on Linux) for access.

## Features

- **Biometric Security**: Leverages macOS `LocalAuthentication`, **Windows Hello**, and **Linux Polkit** for biometric and interactive protection.
- **MCP Server**: Built-in support for the **Model Context Protocol**, allowing AI agents (like Claude or Cursor) to securely access secrets via biometric gates.
- **Keychain Integration**: Stores secrets in the secure macOS Keychain Services, **Windows Credential Manager**, and the **Linux Secret Service DBus**.
- **Binary Whitelisting**: Restricts secret access to cryptographically verified or path-authorized binaries to prevent unauthorized exfiltration.
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

Locksmith ships one fully functional release profile. Official release binaries include full secret lifecycle functionality (read, write, delete, rotate).

The `locksmith_admin` build tag is an internal compile-time mechanism used in source builds and tests. It is not a separate product edition.

> [!WARNING]
> While Locksmith can be used as a Go module, the **Homebrew CLI** is the recommended way to interact with the vault on macOS. 
> Using it as a library requires your host application to have specific signing entitlements to access the macOS Keychain, which can lead to `Permission Denied` errors if not handled correctly.

When importing as a Go module, your build profile determines which compile-time guarded methods are included.




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
bin/locksmith add my-service my-password
```

To support rotator auto-loading, you can store secret context metadata:

```bash
bin/locksmith add github/token my-token \
  --type oauth_token \
  --owner-app github \
  --source-url https://rotation.example.internal/github
```

Rotation uses in-process Go rotators, not shell scripts.

### Retrieving a Secret
```bash
bin/locksmith get my-service
```

### Listing Keys
```bash
bin/locksmith list
```

### Running Commands with Environment Injection (`run`)
Execute any command with biometric-protected secrets injected directly into its environment. Secrets can be specified as environment variables or in an env file (`--env-file`):

Environment syntax supported by `run`:
- `LOCKSMITH_SECRET_<ENV_NAME>=<secret_key>` maps a secret key to an env var name.
- `<ENV_NAME>=locksmith://<secret_key>` resolves a secret URI into that env var.

* **Using `LOCKSMITH_SECRET_` prefix**:
  ```bash
  LOCKSMITH_SECRET_DATABASE_URL=db/password bin/locksmith run -- npm run dev
  ```
  This will fetch the secret for `db/password` and inject it as `DATABASE_URL` for the child process.

* **Using `locksmith://` scheme**:
  ```bash
  DATABASE_URL=locksmith://db/password bin/locksmith run -- npm run dev
  ```

* **Using an environment file**:
  Given a `.env` file:
  ```env
  DATABASE_URL=locksmith://db/password
  STRIPE_KEY=locksmith://stripe/api_key
  ```
  Run with:
  ```bash
  bin/locksmith run --env-file .env -- npm run dev
  ```

### GitHub App Rotation Quick Start

Use this pattern for GitHub token rotation to avoid long-lived PAT bootstrap credentials.

1. Create and install a GitHub App.
   - Organization Settings -> Developer settings -> GitHub Apps -> New GitHub App
   - Grant only minimum required permissions.
   - Install the app on required repositories.
2. Generate an app private key in GitHub App settings and store it securely.
3. Store app credentials directly in Locksmith:
```bash
bin/locksmith add github/app/clientid "Iv1.xxxxx" --type token --owner-app github
bin/locksmith add github/app/installation-id "987654" --type token --owner-app github
bin/locksmith add github/app/private-key "$(cat /secure/path/github-app-private-key.pem)" --type token --owner-app github
```

4. Add a rotation rule:
```yaml
rotation:
  - secret: "github/*"
    rotator: "github-app-installation-token"
    secret_type: "token"
    owner_application: "github"
    source_url: "https://api.github.com/app/installations/<installation_id>/access_tokens"
    metadata:
      github_app_client_id: "locksmith://github/app/clientid"
      # Optional: explicit installation id. If omitted, Locksmith discovers it via /app/installations.
      github_installation_id: "locksmith://github/app/installation-id"
      # Optional when app has multiple installations:
      # github_installation_account: "bonjoski"
      github_app_private_key: "locksmith://github/app/private-key"
    ttl: "24h"
```

5. Store token secrets with selector context so matching is deterministic:
```bash
bin/locksmith add github/ci-token placeholder \
  --type token \
  --owner-app github \
  --source-url https://api.github.com/app/installations/987654/access_tokens
```

6. Rotate without exporting GitHub App credentials to shell env:
```bash
bin/locksmith rotate github/ci-token
```

#### GitHub App Troubleshooting
- `401 Unauthorized` or `403 Forbidden` during rotation:
  - Verify app client ID and installation ID are from the same app.
  - Confirm the app is installed on the target repository/organization.
  - Check app permissions match token usage.
- Multiple installations found error:
  - Set `metadata.github_installation_id` explicitly, or
  - Set `metadata.github_installation_account` to the org/user login to select the right installation.
- Invalid private key or JWT signing errors:
  - Ensure `github/app/private-key` contains the full PEM (including BEGIN/END lines).
- Rule not matching your secret:
  - Confirm secret context matches rule selector (`--type token`, `--owner-app github`, correct `--source-url`).
- Missing metadata reference secret:
  - Confirm each `locksmith://...` key exists in your vault and is readable by Locksmith.

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
- `locksmith_list_secrets`: List names of stored secrets.

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

### SSH & GPG Agent

Locksmith can act as a secure, biometric-protected SSH Agent and GPG Pinentry program to safeguard developer keys and passphrases.

#### SSH Agent
- Start the agent:
  ```bash
  bin/locksmith agent start
  ```
- Set your shell environment:
  ```bash
  export SSH_AUTH_SOCK=~/.locksmith/ssh-agent.sock
  ```
  Add this export to `~/.zshrc` or `~/.bashrc` for persistence.
- Load a key into Locksmith:
  ```bash
  bin/locksmith agent add id_ed25519 ~/.ssh/id_ed25519
  ```
- Use SSH/Git normally:
  ```bash
  ssh -T git@github.com
  git fetch
  ```
  Auth and signature operations will prompt for Touch ID/Windows Hello/Polkit.

#### GPG Pinentry Integration
- Store your GPG passphrase:
  ```bash
  bin/locksmith add gpg/passphrase "<your-passphrase>"
  ```
- Configure gpg-agent in `~/.gnupg/gpg-agent.conf`:
  ```text
  pinentry-program /absolute/path/to/locksmith/bin/pinentry-locksmith
  ```
- Set terminal environment for GPG:
  ```bash
  export GPG_TTY=$(tty)
  ```
  Add this export to `~/.zshrc` or `~/.bashrc` for persistence.
- Reload gpg-agent:
  ```bash
  gpgconf --kill gpg-agent
  ```
- Test Git signing:
  ```bash
  git commit -S -m "signed commit"
  ```
  Pinentry prompts are routed through Locksmith.

#### SSH/GPG Troubleshooting
- SSH auth still bypasses Locksmith:
  - Run `echo "$SSH_AUTH_SOCK"` and confirm it is `~/.locksmith/ssh-agent.sock`.
  - Ensure the agent is running: `bin/locksmith agent start`.
- GPG pinentry does not use Locksmith:
  - Verify `~/.gnupg/gpg-agent.conf` contains exactly:
    `pinentry-program /absolute/path/to/locksmith/bin/pinentry-locksmith`
  - Reload agent: `gpgconf --kill gpg-agent`.
- Terminal signing prompts fail:
  - Set terminal binding: `export GPG_TTY=$(tty)`.
  - Add it to your shell profile for persistence.

## Configuration

Locksmith supports optional configuration via `~/.locksmith/config.yml` for customizing expiration notifications:

```yaml
auth:
  require_biometrics: true  # Enforce Touch ID / Windows Hello
  prompt_message: "Authenticate to Locksmith secret '%s'" # Optional custom prompt 

notifications:
  expiring_threshold: 10d   # Warn when secrets expire within this duration
  method: stderr            # Options: stderr, macos, silent
  show_on_get: true         # Show warnings on 'get' command
  show_on_list: true        # Show status on 'list' command

access_control:
  allow_binaries:
    - "/usr/local/bin/allowed_app"
  deny_binaries:
    - "/usr/bin/forbidden_app"
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
- `expiring_threshold`: Duration formats: `10d` (days), `2w` (weeks), `1mo` (months), `1y` (years), `24h` (hours)
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
gh attestation verify locksmith-darwin-arm64 --repo bonjoski/locksmith
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
