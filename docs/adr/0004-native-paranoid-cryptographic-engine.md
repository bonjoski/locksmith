# ADR-0004: Native Paranoid Cryptographic Engine

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `pkg/ca`, `pkg/locksmith`
- **Deciders:** Lead Security Architect & Cryptographic Systems Engineer

---

## 1. Context & Problem Statement

Cryptographic certificate validation and security checks in legacy tools often rely on external subprocesses (e.g. executing `openssl`, Python scripts, or external CLI helpers).
- Subprocess spawning introduces a 50ms – 100ms "Hop Tax" per operation.
- External dependencies introduce supply-chain vulnerabilities, parsing discrepancies, and potential shell injection vectors.

---

## 2. Decision Outcome

We built a **Pure-Go Native Paranoid Cryptographic Engine** in Locksmith:

1. **In-Memory Pure-Go Cryptography:**
   - Replaced all external subprocess invocations with pure-Go in-memory math (`crypto/x509`, `crypto/ed25519`, `crypto/ecdsa`).
2. **Microsecond Execution (< 50µs):**
   - Cryptographic parameter verification executes in `< 50µs` without child process inception.
3. **Stateless & Lock-Free Design:**
   - Eliminates mutex lock contention across parallel subagents issuing certs or validating SPIFFE identities.

---

## 3. Consequences

- **Positive:** Hop tax dropped by 99.9%; eliminates external OpenSSL/Python runtime dependencies.
- **Negative:** Requires rigorous Go unit and fuzz testing for ASN.1 parsing and certificate validation edge cases.
