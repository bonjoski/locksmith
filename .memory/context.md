# Project Context: Locksmith 🔐

## Current Focus
Initial setup of the `.memory` context system to enhance AI-assisted development.

## Active Tasks
- [x] Create `.memory` directory and populate with initial documentation.
- [ ] Implement a system to auto-update context after significant changes (planned).

## Recent Changes
- Initialized `.memory/` folder.
- Added `project-brief.md`, `tech-stack.md`, `workflows.md`.
- Set "locksmith" as the default project in the current session.

## Important Decisions
- **Context Persistence**: Decided to use the `.memory` folder for persistent AI-readable context within the repository.
- **Admin Build Tag**: Noted that any CLI modifications require the `locksmith_admin` build tag.

## Open Questions
- Should we add a CI job to verify that the `.memory` documentation is up-to-date with code changes?
- Do we need a `CONTRIBUTING.md` that references the `.memory` guidelines?
