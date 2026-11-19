# Locksmith Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, cryptographic models, and hardware security invariants governing [`bonjoski/locksmith`](https://github.com/bonjoski/locksmith).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-in-memory-ephemeral-secret-slicing.md)** | **In-Memory Ephemeral Secret Slicing (`locksmith slice`)** | `Accepted` | 2026-10-30 | `pkg/slice`, `cmd/locksmith` |
| **[ADR-0002](0002-sovereign-spiffe-workload-attestation.md)** | **Sovereign SPIFFE Workload Attestation & Short-Lived Certificates** | `Accepted` | 2026-11-01 | `pkg/spiffe`, `pkg/ca` |
| **[ADR-0003](0003-biometric-step-up-attestation-and-leasing.md)** | **Biometric Step-Up Attestation & Touch ID Amortized Leasing** | `Accepted` | 2026-11-04 | `pkg/stepup`, `pkg/native` |
| **[ADR-0004](0004-native-paranoid-cryptographic-engine.md)** | **Native Paranoid Cryptographic Engine** | `Accepted` | 2026-11-10 | `pkg/ca`, `pkg/locksmith` |

---

## Architectural Principles

1. **Hardware-Enclave Root of Trust:** Private master keys and biometric authentications are anchored directly in hardware security modules (Apple Secure Enclave, Linux TPM2, Windows Hello).
2. **Zero-Disk Secret Exposure:** Credentials are never written to disk unencrypted or exposed in plaintext environment variables visible to `/proc/<pid>/environ`.
3. **Short-Lived Workload Identities:** Workload certificates and SPIFFE SVIDs default to 5-minute lifetimes with automated line-rate rotation.
4. **Deterministic Step-Up Verification:** High-risk actions require cryptographic attestation signed by the local Secure Enclave keypair.
