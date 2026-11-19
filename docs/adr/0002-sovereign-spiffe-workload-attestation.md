# ADR-0002: Sovereign SPIFFE Workload Attestation & Short-Lived Certificates

- **Status:** Accepted
- **Date:** 2026-11-01
- **Component:** `pkg/spiffe`, `pkg/ca`
- **Deciders:** Lead Security Architect & Cryptographic Systems Engineer

---

## 1. Context & Problem Statement

Multi-agent architectures and local sidecars need mutual authentication (mTLS) without relying on permanent, pre-shared static certificates or centralized enterprise public key infrastructure (PKI).
- Permanent certificates introduce multi-day revocation latency when keys leak.
- Connecting local agents to external cloud CAs creates internet latency, availability bottlenecks, and privacy leaks.

---

## 2. Decision Outcome

We implemented a **Sovereign Local SPIFFE CA Engine** in Locksmith:

1. **Local Hardware-Rooted CA:**
   - Locksmith initializes a local subordinate Certificate Authority with keys protected by the Apple Secure Enclave / TPM2.
2. **Short-Lived SVID Issuance:**
   - Agents request SPIFFE Verifiable Identity Documents (X.509 SVIDs) with 5-minute to 1-hour lifetimes (`spiffe://bonjo.dev/agent/<session_id>`).
3. **Sub-Millisecond Line-Rate Issuance:**
   - Local pure-Go issuance over Unix domain sockets or vsock bridges delivers certificate signing in `< 1ms` with zero cloud hops.
4. **RFC 5280 Name Constraints:**
   - Strict Name Constraints confine root trust strictly to `.local` and `localhost` domains, preventing accidental or malicious interception of public TLDs.

---

## 3. Consequences

- **Positive:** Sub-second mTLS bootstrap; automated sub-minute certificate rotation; zero internet dependency.
- **Negative:** System trust store must install the local sovereign root CA for platform-level verification.
