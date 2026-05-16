# Project Context: Locksmith 🔐

## Current Focus
Initial setup of the `.memory` context system to enhance AI-assisted development.

## Active Tasks
- [x] Create `.memory` directory and populate with initial documentation.
- [x] Implement a system to auto-update context after significant changes.
- [x] Integrate Model Context Protocol (MCP) server with 100% biometric enforcement.
- [x] Establish mandatory 100% test coverage policy for new features.

## Recent Changes
- ci: attest all release binaries/ZIPs and correct attestation verification command in documentation
- ci: fix summon binary name in otool verification step
- docs: add summon provider integration badge to readme
- ci(deps): bump github/codeql-action from 4.35.1 to 4.35.5 (#43)
- deps(deps): bump golang.org/x/sys from 0.43.0 to 0.44.0 (#41)

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
