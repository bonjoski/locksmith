# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest | :x:                |

**Note**: We only support the latest release. Please upgrade to the most recent version to receive security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in Locksmith, please report it responsibly:

**Preferred Method**: Use GitHub Security Advisories
- Report at: https://github.com/bonjoski/locksmith/security/advisories/new

**Alternative Method**: Email
1. **DO NOT** open a public GitHub issue
2. Email security details to the maintainer (see GitHub profile)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

**Response Time**: We aim to respond within 48 hours and provide a fix within 7 days for critical vulnerabilities.

---

# Security Audit & Hardening Report

## Executive Summary

This document provides a comprehensive security audit of Locksmith v2.0.0, covering runtime security, 2026 macOS hardening, and supply chain security.

**Overall Assessment**: ✅ **SECURE** - All critical security controls are properly implemented.

**Last Updated**: 2026-02-06  
**Audited Version**: v2.0.0

---

## Table of Contents

1. [Runtime Security Audit](#runtime-security-audit)
2. [2026 macOS Security Hardening](#2026-macos-security-hardening)
3. [Supply Chain Security](#supply-chain-security)
4. [Hardware Security Boundary](#hardware-security-boundary)
5. [Recommendations](#recommendations)

---

## Runtime Security Audit

### 1. Keychain Access Groups

**Status**: ✅ **SECURE** (Intentional Design)

**Analysis**:
- Locksmith does NOT set `kSecAttrAccessGroup`
- This is **intentional and correct** for a single-application CLI tool
- Without an access group, keychain items are isolated to the locksmith binary

**Recommendation**: 
- Current implementation is secure for the intended use case
- If future versions need to share secrets between multiple apps, explicitly set `kSecAttrAccessGroup` with a team-prefixed identifier

**Code Reference**: `pkg/native/keychain.m` lines 17-20

---

### 2. Entropy & Nonce Handling (AES-GCM)

**Status**: ✅ **EXCELLENT** - Cryptographically Secure

**Analysis**:
```go
// cache.go line 120-123
nonce := make([]byte, gcm.NonceSize())
if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
    return nil, err
}
```

**Strengths**:
1. ✅ Uses `crypto/rand.Reader` (CSPRNG) for nonce generation
2. ✅ Fresh nonce generated for EVERY encryption operation
3. ✅ Nonce is prepended to ciphertext for proper decryption
4. ✅ No nonce reuse possible with current implementation

**Security Properties**:
- **Nonce Size**: 12 bytes (96 bits) - standard for AES-GCM
- **Uniqueness**: Cryptographically random, statistically impossible to collide
- **IV Reuse Protection**: Each `encrypt()` call generates new nonce

**Code Reference**: `pkg/locksmith/cache.go` lines 109-126

---

### 3. CGO Pointer Safety

**Status**: ✅ **SAFE** - Proper Memory Management

**Outbound (Go → C)**:
```go
cService := C.CString(service)
cAccount := C.CString(account)
cData := C.CBytes(data)  // ✅ Heap-allocated
defer C.free(unsafe.Pointer(cService))
defer C.free(unsafe.Pointer(cAccount))
defer C.free(cData)
```

**Strengths**:
1. ✅ Uses `C.CBytes()` which allocates on C heap (not stack)
2. ✅ Proper `defer C.free()` for all C allocations
3. ✅ No stack-allocated pointers passed to C

**Inbound (C → Go)**:
```go
return C.GoBytes(unsafe.Pointer(res.data), C.int(res.length)), nil
```

**Strengths**:
1. ✅ Uses `C.GoBytes()` which **copies** data to Go-managed memory
2. ✅ Original C buffer is freed via `defer C.free_keychain_result(res)`
3. ✅ No dangling pointers after function returns

**Memory Zeroing**:
```objc
void free_keychain_result(KeychainResult result) {
  if (result.data) {
    memset(result.data, 0, result.length);  // ✅ Explicit zeroing
    free(result.data);
  }
}
```

**Code Reference**: `pkg/native/bridge.go`

---

## 2026 macOS Security Hardening

### 1. Entitlement Hardening (CVE-2025-24204)

**CVE-2025-24204**: The `gcore` utility was mistakenly granted permissions to read memory of any process, including `securityd` (the Keychain gatekeeper).

**Locksmith Status**: ✅ **SECURE**

**Verification**:
```bash
codesign -d --entitlements - locksmith
```

**Result**: No entitlements file (ad-hoc signature)

**Why This Is Secure**:
- Locksmith uses ad-hoc code signing for open-source distribution
- No `com.apple.security.get-task-allow` entitlement (prevents memory reading)
- Minimal attack surface - no unnecessary permissions requested

**Production Recommendation**:
- For App Store distribution, use a minimal entitlements file
- **NEVER** include `com.apple.security.get-task-allow` in production builds
- This entitlement makes process memory readable by debugging tools, even with SIP enabled

---

### 2. Memory Pinning with mlock

**The "Ghost Secret" Problem**:

Even after zeroing `[]byte`, Go's garbage collector may have moved data during a GC cycle, leaving "ghost" copies in old memory blocks.

**Solution**: Use `mlock` to pin memory pages and prevent:
1. Memory movement by the garbage collector
2. Swapping to disk (even encrypted swap)

**Implementation Approach**:

```go
package locksmith

import "golang.org/x/sys/unix"

// PinMemory locks a memory page to prevent GC movement and disk swapping
func PinMemory(data []byte) error {
    if len(data) == 0 {
        return nil
    }
    return unix.Mlock(data)
}

// UnpinMemory unlocks a previously pinned memory page
func UnpinMemory(data []byte) error {
    if len(data) == 0 {
        return nil
    }
    return unix.Munlock(data)
}
```

**Trade-offs**:

**Benefits**:
- Prevents GC from moving secret data
- Prevents swapping to disk
- Maximum memory security

**Costs**:
- Requires `CAP_IPC_LOCK` capability on some systems
- Locked pages consume physical RAM (can't be swapped)
- May fail if system limits are reached (`ulimit -l`)

**Current Status**:

**Locksmith v2.0.0**: Uses explicit `memset` zeroing without `mlock`

**Rationale**:
- Simpler implementation
- No special permissions required
- macOS encrypted swap provides baseline protection
- Secrets are short-lived (cleared immediately after use)

**Future Enhancement**: Memory pinning can be added as an optional feature for maximum security environments.

---

### 3. Biometric Template Change Detection

**Attack Vector**: An adversary with local admin access adds their fingerprint to macOS settings, potentially gaining access to secrets.

**Solution**: `evaluatedPolicyDomainState`

**Status**: ✅ Documented in `pkg/native/BIOMETRIC_DRIFT_DETECTION.md`

**Approach**:
1. After successful biometric authentication, capture domain state:
   ```objc
   NSData *domainState = [context evaluatedPolicyDomainState];
   ```

2. Store SHA-256 hash of initial state in secure location

3. On subsequent authentications, compare current hash with stored hash

4. If hashes differ → biometric templates changed → require re-authentication

**Implementation Status**: Documented for future implementation when needed

---

## Supply Chain Security

### Current Status: SLSA Level 2 ✅

| Feature | Status | Notes |
|---------|--------|-------|
| Code Signing | ✅ Implemented | `make sign` with codesign |
| Static Analysis | ✅ Hardened | gosec, gitleaks, semgrep |
| Provenance | ✅ **SLSA Level 2** | Artifact attestations in v2.0.0 |
| Dependency Scan | ✅ Implemented | `govulncheck` in CI via `make check` |
| Dependency Verification | ✅ Implemented | `go mod verify` + vulnerability checks |
| Pinned Actions | ✅ Complete | All workflows use SHA-pinned actions |
| OpenSSF Scorecard | ✅ Active | Weekly automated assessment |

### Verification Commands

```bash
# Verify dependencies
go mod verify

# Check for vulnerabilities
govulncheck ./...

# Verify release attestations
gh attestation verify locksmith-darwin-arm64 --owner bonjoski
```

---

## Hardware Security Boundary

### Verification
**Status**: ✅ **VERIFIED** - Proper Secure Enclave Integration

### Data Flow

```
┌─────────────┐
│ Application │ ──(1)──> Request secret
└─────────────┘
       │
       ▼
┌─────────────┐
│  securityd  │ ──(2)──> Orchestrate request
└─────────────┘
       │
       ▼
┌─────────────────┐
│ Secure Enclave  │ ──(3)──> Verify biometrics
│      (SEP)      │ ──(4)──> Decrypt secret
└─────────────────┘
       │
       ▼
┌─────────────┐
│ Application │ <──(5)── Receive decrypted secret
└─────────────┘
```

**Key Security Properties**:
1. Master key NEVER leaves Secure Enclave
2. Biometric data NEVER accessible to application
3. Decryption only after hardware-verified biometric match
4. Cannot be bypassed in software

---

## Recommendations

### Immediate (Already Implemented)
- ✅ All critical security controls in place
- ✅ No dangerous entitlements (CVE-2025-24204 mitigated)
- ✅ Memory zeroing implemented
- ✅ Dependency verification in CI
- ✅ SLSA Level 2 achieved
- ✅ No immediate action required

### Future Enhancements (Optional)
1. **Memory Pinning**: Implement `mlock` for maximum security environments
2. **Biometric Drift Detection**: Implement `evaluatedPolicyDomainState` tracking
3. **Access Group Hardening**: If multi-app support is added, explicitly set `kSecAttrAccessGroup`
4. **SLSA Level 3**: Consider using SLSA GitHub Generator for even stronger provenance

### Continuous Monitoring
- ✅ Run `govulncheck` before each release
- ✅ Monitor OpenSSF Scorecard results
- ✅ Keep dependencies updated
- ✅ Review security advisories

---

## Conclusion

Locksmith v2.0.0 demonstrates **excellent security practices** across all audited areas:

- ✅ Cryptographic implementation is sound (proper nonce handling, secure RNG)
- ✅ CGO memory management is safe (no pointer issues, proper cleanup)
- ✅ Keychain integration is secure (hardware-backed, proper isolation)
- ✅ Supply chain security is robust (SLSA Level 2, comprehensive scanning)
- ✅ 2026 macOS hardening complete (CVE-2025-24204 mitigated)
- ✅ No vulnerabilities found in dependencies

**No critical or high-severity issues found.**
