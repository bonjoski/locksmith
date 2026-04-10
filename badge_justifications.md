# OpenSSF Best Practices Badge: Justification Crib Sheet 🔐

This document provides the technical justifications for the **Locksmith** OpenSSF Best Practices Badge application. You can copy/paste these responses directly into the questionnaire at [bestpractices.coreinfrastructure.org](https://bestpractices.coreinfrastructure.org/).

---

### [crypto_published] Cryptographic Protocols
**Met**
**Justification**: Locksmith delegates all primary cryptographic operations to established OS-native security frameworks: macOS Keychain Services (SecItem/SecKey) and Windows Credential Manager/BCrypt. These frameworks exclusively use peer-reviewed and published algorithms such as AES-256 and P-256 ECC.
**Key URL**: https://developer.apple.com/documentation/security/keychain_services

### [crypto_call] No Re-implementation
**Met**
**Justification**: Locksmith is a secret-management utility, not a cryptographic library. It does not implement any custom cryptographic primitives; it calls only the Go standard library `crypto` package and the aforementioned OS security APIs.

### [crypto_floss] FLOSS Implementation
**Met**
**Justification**: The core logic is built in Go (BSD-3 License). While the project leverages platform-specific hardware (Secure Enclave, TPM), the software layer and all cryptographic bridges are implementable and buildable using 100% FLOSS toolchains (Go, LLVM/Clang, GCC).

### [crypto_keylength] Key Lengths
**Met**
**Justification**: Locksmith uses AES-256 for secondary encryption layers and relies on the OS default keylengths for primary storage (typically 256-bit or better), exceeding NIST requirements through 2030.

### [crypto_working] No Broken Algorithms
**Met**
**Justification**: Locksmith does not use MD4, MD5, RC4, or single DES for any security functionality. It strictly adheres to SHA-2 (SHA-256) and AES-GCM for all internal data integrity and encryption tasks.
**Key URL**: https://pkg.go.dev/crypto

### [crypto_weaknesses] No Known Weaknesses
**Met**
**Justification**: We enforce a modern architecture (`v2`) that explicitly avoids legacy ciphers with known weaknesses (like CBC in certain contexts) in favor of authenticated encryption (AEAD) modes like AES-GCM.

### [crypto_pfs] Perfect Forward Secrecy
**N/A**
**Justification**: Perfect Forward Secrecy is a property of key agreement protocols (like TLS). Locksmith is a local "at-rest" storage vault and does not implement network-based key exchange protocols.

### [crypto_password_storage] Password Hashing
**N/A**
**Justification**: Locksmith does not store passwords for the authentication of external users. It is a client-side vault that delegates local user authentication to the operating system's biometric and hardware-backed services.

### [crypto_random] Secure RNG
**Met**
**Justification**: All cryptographic nonces and random values are generated using the Go `crypto/rand` package, which interface directly with the cryptographically secure random number generators provided by the underlying OS kernels (/dev/urandom, BCryptGenRandom).

### [delivery_mitm] Secure Delivery
**Met**
**Justification**: All distribution channels (GitHub Releases, Homebrew Tap) use HTTPS exclusively to prevent man-in-the-middle attacks during delivery.

### [delivery_unsigned] Signed Releases
**Met**
**Justification**: All releases are cryptographically signed using GPG and include **GitHub Artifact Attestations** (SLSA Level 2). Verification instructions are provided in the `RELEASING.md` file.
**Key URL**: https://github.com/bonjoski/locksmith/blob/main/RELEASING.md

### [vulnerabilities_fixed_60_days] Patch Speed
**Met**
**Justification**: The project maintains a 0-vulnerability baseline. Our Security Policy guarantees that any reported high or medium severity vulnerabilities are addressed well within the 60-day window.

### [no_leaked_credentials] No Leaked Secrets
**Met**
**Justification**: We enforce a mandatory `pre-commit` hook that runs **TruffleHog** and a custom **Entropy Checker** on every file. This prevents any private credentials or high-entropy tokens from being committed to the public repository.
**Key URL**: https://github.com/bonjoski/locksmith/blob/main/scripts/architect-review.sh
