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
- fix(security): eliminate production test seam and close post-v3.2.5 advisory gaps (v3.2.6) (#115)
- fix(security): resolve GHSA-wfmr-rw42-3rv7 residual issues and establish black-box acceptance testbed (v3.2.5) (#114)
- Merge pull request #113 from bonjoski/fix/ghsa-wfmr-rw42-3rv7-gap-closure
- test(spiffe): dynamically resolve runner UID and increase burst limit in concurrency test
- fix(security): close GHSA-wfmr-rw42-3rv7 gaps and bump to v3.2.4

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
