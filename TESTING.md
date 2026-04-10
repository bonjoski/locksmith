# Testing Locksmith 🔐

This document describes the testing strategy and suite for Locksmith. We employ a multi-layered testing approach to ensure reliability, security, and cross-platform compatibility.

## 1. Automated Unit Tests

Our unit tests cover the core logic in `pkg/locksmith`, including config parsing, TTL calculations, and notification logic.

```bash
# Run all unit tests
make test

# Run tests with the admin build tag (for Set/Delete logic)
go test -v -tags locksmith_admin ./...
```

## 2. Manual Biometric Regression Tests

Because biometric authentication (Touch ID, Windows Hello) requires interactive user presence and physical hardware, we use a custom "Manual Regression" suite. These tests prompt the developer to perform actual biometric scans and verify the results.

```bash
# Run manual biometric tests (macOS/Windows)
make test-manual
```

**What these tests verify:**
- Successful authentication returns the secret.
- Cancellation of the biometric prompt returns the correct error.
- Lockout or hardware failure is handled gracefully.

## 3. Security Scanning 🛡️

Our CI/CD pipeline runs multiple security scanners on every commit:

- **TruffleHog**: Scans the git history and current diff for accidentally committed secrets.
- **Gosec**: Performs static analysis for security vulnerabilities in Go code (e.g., weak crypto, unsafe pointers).
- **Semgrep**: Checks for project-specific security anti-patterns (e.g., non-v2 internal imports).
- **Entropy Checker**: A custom Go-based tool that detects high-entropy strings (potential leaked keys) that might be missed by generic pattern matching.

## 4. Architectural Gating

We use the **Architect Review Agent** (`scripts/architect-review.sh`) to enforce standards that cannot be caught by simpler tools:

- **Cyclomatic Complexity**: Functions must stay below a complexity of 15.
- **Memory Safety**: Ensuring that raw `[]byte` secrets are paired with memory clearing patterns.
- **Component Siloing**: Strict enforcement of internal package boundaries.

## 5. Continuous Fuzzing 🌪️

We use **GitHub Actions Fuzzing** to continuously stress-test our data parsing and configuration logic. This helps identify edge cases and potential memory corruption bugs in our CGO bridges.

## 6. How to Contribute Tests

- When adding a feature, include unit tests in the same package.
- If the feature requires biometric interaction, add a test case to `cmd/locksmith/cmd/regression_test.go` using the `manual_test` build tag.
- All new code must pass `make check` before submission.
