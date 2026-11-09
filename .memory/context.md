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
- chore(release): bump dependencies, desktop UI, and version to v3.2.8
- ci(deps): bump actions/setup-node from 4.4.0 to 7.1.0 (#107)
- ci(deps): bump github/codeql-action/analyze from 4.37.9 to 4.39.1 (#105)
- ci(deps): bump github/codeql-action/upload-sarif from 4.37.7 to 4.39.1 (#106)
- ci(deps): bump ossf/scorecard-action from 2.4.4 to 2.5.0 (#108)

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
