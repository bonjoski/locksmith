# AI Development Guidelines: Locksmith 🔐

These guidelines are designed to ensure consistency and security when developing Locksmith with AI assistance.

## Security First

- **Memory Zeroing**: Always ensure sensitive data (passwords, tokens, keys) is zeroed out in memory immediately after use. Use `defer` patterns for safety.
- **Biometric Enforcement**: Never bypass biometric checks for read/write operations unless explicitly requested for testing.
- **Dependency Pinning**: Always use pinned SHAs for GitHub Actions and specific versions for Go modules.

## Coding Standards

- **Internal Imports**: Always use the `/v2` path for internal package imports (e.g., `github.com/bonjoski/locksmith/v2/pkg/locksmith`).
- **Build Tags**: Use `// +build locksmith_admin` (or modern `//go:build locksmith_admin`) for any code that performs write/delete operations.
- **Error Handling**: Use `fmt.Errorf("...: %w", err)` for error wrapping to maintain context.

## AI Interaction

- **Context Preservation**: Update `.memory/context.md` after completing significant tasks or making architectural decisions.
- **Verification**: Always run `make check` and `make test` before declaring a task complete.
- **Artifacts**: Use markdown artifacts for complex plans and summaries, but keep files in `.memory/` for long-term repo knowledge.

## Project Patterns

- **Provider Pattern**: When adding support for a new OS or backend, follow the existing interface in `pkg/locksmith/locksmith.go` (`Backend` interface).
## Testing Strategy

- **Mandatory Coverage**: All new features must be accompanied by unit tests.
- **Mocking**: Use mock implementations for the `Backend` and `Cache` interfaces to ensure tests can run in CI environments without hardware dependencies.
- **MCP Testing**: Use `mcp.NewInMemoryTransports()` for end-to-end testing of tool handlers without requiring network or file descriptors.
- **Build Tags**: Remember to include `//go:build locksmith_admin` in test files that test administrative features.
