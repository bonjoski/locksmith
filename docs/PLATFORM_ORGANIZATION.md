# Platform Organization

This document describes how Locksmith organizes platform-specific (OS) code.

## Go Source Files with Build Tags

Go requires files in the same package to reside in the same directory, so OS-specific Go files are in their respective package directories with platform-specific names:

### Locksmith Package (`pkg/locksmith/`)

- **masterkey_darwin.go** - macOS keychain integration via LocalAuthentication
- **masterkey_linux.go** - Linux secret service integration
- **masterkey_windows.go** - Windows credential manager integration
- **run_signals_unix.go** - Signal handling for Unix-like systems
- **run_signals_windows.go** - Signal handling for Windows

Each file uses Go build tags (e.g., `//go:build darwin`) to control compilation per OS.

### Native Package (`pkg/native/`)

- **bridge_darwin.go** - macOS native binding bridge
- **bridge_linux.go** - Linux native binding bridge
- **bridge_windows.go** - Windows native binding bridge
- **keychain_darwin.h** - macOS Keychain Services header
- **keychain_darwin.m** - macOS Keychain Services implementation (Objective-C)

## Platform-Specific Scripts

Scripts and tools organized by platform:

```
scripts/
├── dev/                  # Development utilities
│   ├── architect-review.sh
│   ├── entropy-checker/
│   ├── rotate-gh-token.sh
│   └── update-context.sh
├── platform/
│   └── macos/           # macOS-specific scripts
│       ├── package_macos.sh    # Create macOS .app bundles
│       └── update_homebrew_sha.sh  # Update Homebrew package SHA
├── security/            # Security scanning
│   └── govulncheck-guard.sh
└── ci/                  # CI/CD scripts (reserved for future use)
```

## Build Constraints

Go uses build constraints to conditionally compile code. The `//go:build` directive at the top of each OS-specific file determines when it's compiled:

```go
//go:build darwin
// +build darwin

package locksmith
```

This file only compiles on macOS.

### Supported Build Tags

- `darwin` - macOS
- `linux` - Linux
- `windows` - Windows  
- `unix` - Unix-like systems (macOS, Linux, BSD, etc.)
- `!windows` - Everything except Windows

## Building for Specific Platforms

To build for a specific platform:

```bash
# macOS ARM64
GOOS=darwin GOARCH=arm64 make build

# Linux AMD64
GOOS=linux GOARCH=amd64 make build

# Windows AMD64
GOOS=windows GOARCH=amd64 make build
```

Use the `make release` target to build for all supported platforms.

## Adding New Platform Support

1. Create a new OS-specific file with the pattern `*_<os>.go`
2. Add the appropriate `//go:build` directive
3. Declare the same package as other files
4. Place in the same directory as other package files
5. Test with `GOOS=<os> go build ./...`
