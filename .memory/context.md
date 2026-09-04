# Project Context: Locksmith 🔐

## Current Focus
Implementing roadmap features (next: Application-Level Access Control / Binary Whitelisting).

## Active Tasks
- [x] Create `.memory` directory and populate with initial documentation.
- [x] Implement a system to auto-update context after significant changes.
- [x] Integrate Model Context Protocol (MCP) server with 100% biometric enforcement.
- [x] Establish mandatory 100% test coverage policy for new features.
- [x] Implement in-memory environment injection (`run` command) with full tests.
- [x] Implement biometric-protected SSH & GPG agent (Feature #2) with full tests.
- [x] Implement Rotation Hooks & Auto-Rotation (Feature #5) with full tests.
- [ ] Implement Application-Level Access Control / Binary Whitelisting (Feature #3).

## Recent Changes
- fix: skip keychain write when git credential unchanged
- chore: update Go toolchain to 1.26.6 and golang.org/x/crypto to v0.55.0
- chore: bump version to 2.7.12
- fix: only enable OnlyCached for credential get, not store
- chore: bump version to 2.7.11

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
