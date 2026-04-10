# Project Context: Locksmith 🔐

## Current Focus
Initial setup of the `.memory` context system to enhance AI-assisted development.

## Active Tasks
- [x] Create `.memory` directory and populate with initial documentation.
- [ ] Implement a system to auto-update context after significant changes (planned).

## Recent Changes
- docs: link official OpenSSF Best Practices badge 12451
- docs: add OpenSSF badge justification crib sheet
- docs: finalize OpenSSF Best Practices (CII) compliance
- fix: remove disallowed CodeQL init from scorecard workflow
- fix: resolve recursive doc sync with structural-only CI gating

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context.
- **Review Gating**: Implemented mandatory pre-commit gating for architectural compliance (v2 imports, memory zeroing, build tags).
- **Environment**: Recognized standard Bash environment for project automation.

## Open Questions
- **SHA Generation**: Need to run `make release` and update Homebrew SHAs once binaries are notarized.
- **PR Agent Extension**: Should we add more "Deep Checks" (e.g., complexity metrics or entropy checks)?
