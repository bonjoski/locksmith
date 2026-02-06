# Runtime Security Audit Report

## Executive Summary

This audit examines the runtime security of Locksmith v2.0.0, focusing on keychain access controls, cryptographic implementation, and CGO memory safety.

**Overall Assessment**: ✅ **SECURE** - All critical security controls are properly implemented.

---

## 1. Keychain Access Groups

### Finding
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

## 2. Entropy & Nonce Handling (AES-GCM)

### Finding
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

## 3. CGO Pointer Safety

### Finding
**Status**: ✅ **SAFE** - Proper Memory Management

**Analysis**:

#### Outbound (Go → C)
```go
// bridge.go lines 15-20
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

#### Inbound (C → Go)
```go
// bridge.go line 46
return C.GoBytes(unsafe.Pointer(res.data), C.int(res.length)), nil
```

**Strengths**:
1. ✅ Uses `C.GoBytes()` which **copies** data to Go-managed memory
2. ✅ Original C buffer is freed via `defer C.free_keychain_result(res)`
3. ✅ No dangling pointers after function returns

#### Memory Zeroing
```objc
// keychain.m lines 283-291
void free_keychain_result(KeychainResult result) {
  if (result.data) {
    memset(result.data, 0, result.length);  // ✅ Explicit zeroing
    free(result.data);
  }
}
```

**Code Reference**: `pkg/native/bridge.go`

---

## 4. Supply Chain Security Status

| Feature | Status | Notes |
|---------|--------|-------|
| Code Signing | ✅ Implemented | `make sign` with codesign |
| Static Analysis | ✅ Hardened | gosec, gitleaks, semgrep |
| Provenance | ✅ **SLSA Level 2** | Artifact attestations in v2.0.0 |
| Dependency Scan | ✅ Implemented | `govulncheck` in CI via `make check` |
| Pinned Actions | ✅ Complete | All workflows use SHA-pinned actions |
| OpenSSF Scorecard | ✅ Active | Weekly automated assessment |

---

## 5. Hardware Security Boundary

### Verification
**Status**: ✅ **VERIFIED** - Proper Secure Enclave Integration

**Flow**:
1. **Request**: App calls `SecItemCopyMatching`
2. **Challenge**: `securityd` daemon requests biometric proof from Secure Enclave
3. **Verification**: Touch ID sensor sends cryptographic proof to SEP
4. **Response**: Only after SEP verification does the decryption key release
5. **Delivery**: Decrypted payload returned to locksmith

**Key Security Properties**:
- Master key NEVER leaves Secure Enclave
- Biometric data NEVER accessible to application
- Hardware-backed attestation cannot be bypassed in software

---

## Recommendations

### Immediate (Already Implemented)
- ✅ All critical security controls in place
- ✅ No immediate action required

### Future Enhancements (Optional)
1. **Biometric Drift Detection**: Implement `evaluatedPolicyDomainState` tracking (documented in BIOMETRIC_DRIFT_DETECTION.md)
2. **Access Group Hardening**: If multi-app support is added, explicitly set `kSecAttrAccessGroup`
3. **SLSA Level 3**: Consider using SLSA GitHub Generator for even stronger provenance

---

## Conclusion

Locksmith v2.0.0 demonstrates **excellent security practices** across all audited areas:

- Cryptographic implementation is sound (proper nonce handling, secure RNG)
- CGO memory management is safe (no pointer issues, proper cleanup)
- Keychain integration is secure (hardware-backed, proper isolation)
- Supply chain security is robust (SLSA Level 2, comprehensive scanning)

**No critical or high-severity issues found.**

---

**Audit Date**: 2026-02-06  
**Audited Version**: v2.0.0  
**Auditor**: Automated Security Review
