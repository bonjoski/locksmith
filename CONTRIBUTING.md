# Contributing to Locksmith 🔐

First off, thank you for considering contributing to Locksmith! It's people like you that make Locksmith such a great tool for the community.

## Security First

As a security-focused tool, we have strict requirements for contributions:

1.  **Vulnerability Reporting**: If you find a security hole, please **DO NOT** open an issue. Follow our [Security Policy](SECURITY.md) instead.
2.  **Signed Commits**: All commits must be **GPG-signed**. We do not accept unsigned contributions.
3.  **Memory Safety**: Pay close attention to memory zeroing and CGO bridge safety. See [architect-review.sh](scripts/architect-review.sh) for Automated Gating.

## Development Workflow

### Prerequisites

- Go v1.25.4+
- `make`
- Tooling: `golangci-lint`, `gosec`, `trufflehog` (installed automatically via `make check`)

### Build and Test

```bash
# Run all quality and security checks
make check

# Run unit tests
make test

# Build for your platform
make build
```

### Pull Request Process

1.  Create a branch from `main`.
2.  Ensure `make check` passes locally.
3.  Include unit tests for new logic.
4.  Update documentation in `.memory/` if architecture or dependencies change (run `./scripts/update-context.sh`).
5.  Open a PR and ensure all CI checks pass.

## Code of Conduct

Help us keep Locksmith a welcoming and professional project! We follow standard open-source community guidelines.

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
