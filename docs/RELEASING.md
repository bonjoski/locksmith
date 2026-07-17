# Releasing Locksmith

This document describes the release process for Locksmith, including how to create releases and verify their authenticity. This project adheres to **[Semantic Versioning (SemVer)](https://semver.org/spec/v2.0.0.html)**.

## Creating a Release

Releases are automated via GitHub Actions. To create a new release:

1. **Update the version** in `pkg/locksmith/version.go`:
   ```go
   const Version = "1.5.1"
   ```

2. **Commit and push** the version change:
   ```bash
   git add pkg/locksmith/version.go
   git commit -m "chore: bump version to v1.5.1"
   git push origin main
   ```

3. **Create and push a signed tag**:
   ```bash
   git tag -s v1.5.1 -m "Release v1.5.1"
   git push origin v1.5.1
   ```

   Or use the one-command helper target:
   ```bash
   make release-tag TAG=v1.5.1
   ```

4. The GitHub Actions workflow will automatically:
   - Build binaries for macOS (ARM64, AMD64) and Windows (AMD64, ARM64)
   - Sign the macOS binaries with ad-hoc signatures
   - Generate cryptographic attestations (SLSA provenance) for all binaries
   - Create a GitHub release with all artifacts

## PR-Based Release Prep (Recommended)

Use a pull request for release-preparation changes (workflow updates, signing policy updates, docs updates) instead of pushing directly to `main`.

1. Create a branch from `main`:
   ```bash
   git checkout -b chore/release-prep
   ```

2. Commit with a verified signature:
   ```bash
   git add <files>
   git commit -S -m "chore: release prep updates"
   ```

3. Push and open a PR:
   ```bash
   make open-pr
   ```

   Optional custom PR title/body:
   ```bash
   make open-pr TITLE="chore: release prep" BODY="Signed release process updates"
   ```

## Verifying Releases

Locksmith releases include cryptographic attestations that prove the binaries were built by the official GitHub Actions workflow.

### Using GitHub CLI (Recommended)

```bash
# Download the binary (example for macOS)
gh release download v1.5.1 -p 'locksmith-darwin-arm64'

# Verify the attestation
gh attestation verify locksmith-darwin-arm64 --repo bonjoski/locksmith

# Example for Windows
gh release download v1.5.1 -p 'locksmith-windows-amd64.exe'
gh attestation verify locksmith-windows-amd64.exe --repo bonjoski/locksmith
```

This verifies:
- The binary was built by the official GitHub Actions workflow
- The binary hasn't been tampered with since it was built
- The binary corresponds to the tagged source code

```bash
# Download checksums
gh release download v1.5.1 -p 'checksums.txt'

# Verify the checksum
shasum -a 256 -c checksums.txt
```

### Using GPG (Traditional Verification)

Before verifying, import the public key included in the repository:
```bash
gpg --import public.gpg
```

Then, verify the detached signature for any binary or the checksum file:
```bash
# Verify the checksums file signature
gh release download v1.5.1 -p 'checksums.txt.asc'
gpg --verify checksums.txt.asc checksums.txt

# Verify a binary signature
gh release download v1.5.1 -p 'locksmith-darwin-arm64.asc'
gpg --verify locksmith-darwin-arm64.asc locksmith-darwin-arm64
```

## Local Release Build (Testing)

To test the release build locally:

```bash
make release
```

This creates binaries in the `bin/` directory with checksums.

## Security Notes

- **Attestations**: Each release includes cryptographic attestations that link the binary to its source code and build process.
- **SLSA Level 2**: Our release process meets SLSA Level 2 requirements for supply chain security.
- **Code Signing**: Binaries are signed with ad-hoc signatures. For production use, users should verify attestations.

## Troubleshooting

### Workflow Fails

If the release workflow fails:
1. Check the Actions tab for error details
2. Ensure the tag follows the `v*` pattern (e.g., `v1.5.1`)
3. Ensure the tag is a signed annotated tag (lightweight tags are rejected)
4. Verify Go version compatibility in `.github/workflows/release.yml`

### Attestation Verification Fails

If attestation verification fails:
1. Ensure you have the latest GitHub CLI: `gh --version`
2. Check that you downloaded the binary from the official repository
3. Verify the binary hasn't been modified after download
