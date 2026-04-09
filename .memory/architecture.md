# Project Architecture: Locksmith 🔐

This document provides a visual and conceptual overview of how Locksmith components interact.

## Component Overview

The following diagram illustrates the relationship between the CLI entry points, the core library, and the native platform bridges.

```mermaid
graph TD
    subgraph "Interface Layer (cmd/)"
        CLI[locksmith cmd]
        Summon[summon-locksmith]
    end

    subgraph "Core Logic (pkg/locksmith)"
        LS[Locksmith Controller]
        Cache[Disk Cache (AES-GCM)]
        Model[Secret/Metadata Models]
    end

    subgraph "Native Bridge (pkg/native)"
        Bridge[Platform Bridge]
        Darwin[macOS Keychain + LocalAuth]
        Windows[Windows Credential Manager + Hello]
        Linux[Linux Secret Service + Polkit]
    end

    CLI --> LS
    Summon --> LS
    LS --> Cache
    LS --> Model
    LS --> Bridge
    Bridge --> Darwin
    Bridge --> Windows
    Bridge --> Linux
    Cache -.->|Encrypted files| Disk[~/.locksmith/cache/]
```

## Data Flow: Retrieving a Secret

1. **Request**: CLI or Summon requests a secret by key.
2. **Cache Check**: `pkg/locksmith` checks the local disk cache (`~/.locksmith/cache/`).
    - If valid and not expired, the secret is decrypted using the Master Key and returned.
3. **Keychain Fallback**: If cache miss/expired, `pkg/locksmith` calls the `Native Bridge`.
4. **Biometric Auth**: The `Native Bridge` triggers a platform-specific biometric prompt (e.g., Touch ID).
5. **Secure Retrieval**: Upon successful auth, the platform keychain returns the encrypted data.
6. **Persistence**: The secret is returned to the user and re-cached for the duration of the TTL.

## Security Boundaries

- **Biometric Enforcement**: Occurs within the `pkg/native` layer or via the OS-level Keychain Access Control Lists (ACLs).
- **Encryption at Rest**:
    - **Keychain**: Handled by the OS (Secure Enclave/TPM).
    - **Cache**: Handled by `pkg/locksmith/cache.go` using AES-256-GCM with a hardware-derived master key.
- **Memory**: Sensitive data is zeroed in `pkg/locksmith` and `pkg/native` after operations.
