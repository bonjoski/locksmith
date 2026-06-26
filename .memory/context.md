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
- [ ] Implement Application-Level Access Control / Binary Whitelisting (Feature #3).

## Recent Changes
- chore: bump version to v2.5.0
- feat: implement biometric-protected SSH & GPG agent (#55)
- feat: implement in-memory environment injection (run command) (#54)
- deps(deps): bump golang.org/x/term to v0.44.0 and github.com/modelcontextprotocol/go-sdk to v1.6.1
- deps(deps): bump golang.org/x/sys from 0.44.0 to 0.46.0 (#49)

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
