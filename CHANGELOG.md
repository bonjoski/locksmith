# Changelog 📖

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.0] - 2026-04-15

### Added
- **Model Context Protocol (MCP)**: Fully integrated biometric-gated MCP server allowing AI agents to securely interact with Locksmith.
- **Testing Architecture**: Established mandatory test coverage mandate for new features with standardized biometric backend mocking.
- **Unit Test Suite**: New comprehensive tests for MCP tools achieving >84% statement coverage.
- **Architectural Gating**: Integrated `gocyclo` and custom entropy scanning into `make check`.
- **Pre-commit Automation**: Hardened `pre-commit` hook that auto-syncs AI context documentation and enforces security standards.
- **Biometric Regression Suite**: Added manual biometric testing infrastructure for macOS and Windows.
- **Documentation**: New `TESTING.md`, `SECURITY.md`, and `CONTRIBUTING.md` for OpenSSF/CII Best Practices compliance.

### Changed
- **MCP Refactoring**: Extracted core server logic to `newMCPServer` for enhanced testability.
- **2026 Action Upgrade**: All GitHub Actions upgraded to native v6/v7 with absolute commit SHA pinning.
- **Supply Chain Hardening**: Standardized on SLSA Level 2 provenance and mandatory GPG signature enforcement.
- **Scorecard v2.4.3**: Upgraded OpenSSF Scorecard infrastructure and resolved verification failures.

## [2.2.5] - 2026-04-09

### Added
- Initial support for Go 1.25 runtime.
- macOS Notarization pipeline integration.

## [2.2.0] - 2026-03-15

### Changed
- **Major Architecture**: Migrated to Go Module v2.
- **Windows Support**: Added native Windows Hello biometric support.
- **Linux Support**: Added Polkit/Secret Service integration.
