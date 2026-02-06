# 2026 macOS Security Hardening Guide

This document addresses critical security considerations for macOS applications in 2026, including CVE-2025-24204 and advanced memory protection techniques.

---

## 1. Entitlement Hardening (CVE-2025-24204)

### The gcore Vulnerability
**CVE-2025-24204**: The `gcore` utility was mistakenly granted permissions to read memory of any process, including `securityd` (the Keychain gatekeeper).

### Locksmith Status: ✅ SECURE

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

## 2. Memory Pinning with mlock

### The "Ghost Secret" Problem

**Issue**: Even after zeroing `[]byte`, Go's garbage collector may have moved data during a GC cycle, leaving "ghost" copies in old memory blocks.

**Solution**: Use `mlock` to pin memory pages and prevent:
1. Memory movement by the garbage collector
2. Swapping to disk (even encrypted swap)

### Implementation Approach

```go
package locksmith

import (
    "golang.org/x/sys/unix"
)

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

// SecureSecret wraps a secret with memory pinning
type SecureSecret struct {
    data   []byte
    pinned bool
}

func NewSecureSecret(data []byte) (*SecureSecret, error) {
    s := &SecureSecret{data: data}
    if err := PinMemory(s.data); err != nil {
        return nil, err
    }
    s.pinned = true
    return s, nil
}

func (s *SecureSecret) Zero() error {
    if len(s.data) > 0 {
        // Zero the data
        for i := range s.data {
            s.data[i] = 0
        }
        
        // Unpin the memory
        if s.pinned {
            if err := UnpinMemory(s.data); err != nil {
                return err
            }
            s.pinned = false
        }
    }
    s.data = nil
    return nil
}
```

### Trade-offs

**Benefits**:
- Prevents GC from moving secret data
- Prevents swapping to disk
- Maximum memory security

**Costs**:
- Requires `CAP_IPC_LOCK` capability on some systems
- Locked pages consume physical RAM (can't be swapped)
- May fail if system limits are reached (`ulimit -l`)

### Current Status

**Locksmith v2.0.0**: Uses explicit `memset` zeroing without `mlock`

**Rationale**:
- Simpler implementation
- No special permissions required
- macOS encrypted swap provides baseline protection
- Secrets are short-lived (cleared immediately after use)

**Future Enhancement**: Memory pinning can be added as an optional feature for maximum security environments.

---

## 3. Biometric Template Change Detection

### Attack Vector
An adversary with local admin access adds their fingerprint to macOS settings, potentially gaining access to secrets.

### Solution: `evaluatedPolicyDomainState`

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

## 4. Supply Chain Security (SLSA)

### Current Status: SLSA Level 2 ✅

| Feature | Status |
|---------|--------|
| Artifact Attestations | ✅ Implemented in `release.yml` |
| Vulnerability Scanning | ✅ `govulncheck` in CI |
| Dependency Verification | ✅ `go mod verify` in CI |
| Pinned Actions | ✅ All workflows use SHA pins |
| OpenSSF Scorecard | ✅ Weekly assessment |

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

## 5. Secure Enclave Architecture

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

## Recommendations Summary

### Immediate (Completed)
- ✅ Entitlements audit (no dangerous entitlements)
- ✅ Memory zeroing implemented
- ✅ Dependency verification in CI
- ✅ SLSA Level 2 achieved

### Future Enhancements (Optional)
- 🔄 Memory pinning with `mlock` for maximum security
- 🔄 Biometric drift detection implementation
- 🔄 SLSA Level 3 with dedicated builder

### Continuous
- ✅ Run `govulncheck` before each release
- ✅ Monitor OpenSSF Scorecard results
- ✅ Keep dependencies updated

---

**Last Updated**: 2026-02-06  
**Locksmith Version**: v2.0.0
