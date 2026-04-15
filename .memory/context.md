# Project Context: Locksmith 🔐

## Current Focus
Initial setup of the `.memory` context system to enhance AI-assisted development.

## Active Tasks
- [x] Create `.memory` directory and populate with initial documentation.
- [x] Implement a system to auto-update context after significant changes.
- [x] Integrate Model Context Protocol (MCP) server with 100% biometric enforcement.
- [x] Establish mandatory 100% test coverage policy for new features.

## Recent Changes
- Merge remote-tracking branch 'origin/dependabot/github_actions/softprops/action-gh-release-3.0.0'
- Merge remote-tracking branch 'origin/dependabot/github_actions/anchore/sbom-action-0.24.0'
- Merge remote-tracking branch 'origin/dependabot/github_actions/actions/upload-artifact-7.0.1'
- chore(deps): merge dependabot updates
- ci(deps): bump actions/upload-artifact from 7.0.0 to 7.0.1

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **Biometric Mocking**: Explore more standardized mocking patterns for native backends to maintain 100% coverage in CI.
