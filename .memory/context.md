# Project Context: Locksmith 🔐

## Current Focus
Initial setup of the `.memory` context system to enhance AI-assisted development.

## Active Tasks
- [x] Create `.memory` directory and populate with initial documentation.
- [x] Implement a system to auto-update context after significant changes.
- [x] Integrate Model Context Protocol (MCP) server with 100% biometric enforcement.
- [x] Establish mandatory 100% test coverage policy for new features.

## Recent Changes
- deps(deps): bump golang.org/x/sys from 0.44.0 to 0.46.0 (#49)
- ci(deps): bump github/codeql-action from 4.35.5 to 4.36.2 (#51)
- ci(deps): bump softprops/action-gh-release from 3.0.0 to 3.0.1 (#52)
- ci(deps): bump actions/checkout from 6.0.2 to 7.0.0 (#53)
- Fix broken spec diagram

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
