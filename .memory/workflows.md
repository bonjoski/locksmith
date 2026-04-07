# Development Workflows: Locksmith 🔐

## Building and Signing

### Build (Local)
Builds the `locksmith` binary with the `locksmith_admin` tag.
```bash
make build
```

### Sign (macOS)
Signs the binary with a developer identity (defaults to ad-hoc signing `-`).
```bash
make sign
```

### Build Summon Provider
```bash
make build-summon
```

## Testing and Quality

### Run Unit Tests
```bash
make test
```

### Run Manual Biometric Tests (macOS)
Requires user interaction for Touch ID verification.
```bash
make test-manual
```

### Run Full Check Suite
Recommended before pushing any changes.
```bash
make check
```

## Release Management

### Build Release Artifacts
Builds binaries and app bundles for all supported platforms (darwin, windows, linux).
```bash
make release
```

### Install Summon Provider (Local)
Installs the `summon-locksmith` provider to `/usr/local/lib/summon/locksmith`.
```bash
make install-summon
```

## Maintenance

### Tidy Modules
```bash
make tidy
```

### Clean Up Artifacts
```bash
make clean
```
