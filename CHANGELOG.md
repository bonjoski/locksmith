# Changelog

All notable changes to `locksmith` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.2.0] - 2026-11-01

### Added
- **Sovereign SPIFFE X.509-SVID Issuance (`locksmith ca issue --spiffe`):**
  - Issuance of ephemeral SPIFFE IDs with sub-hour TTLs (5m to 24h).
  - Classical (ECDSA P-256), Post-Quantum (ML-DSA-65 FIPS 204), and Dual-Root certificate bundles.
  - Automatic 5-minute clock-skew buffer on certificate activation windows.
- **Atomic Container Export & Auto-Rotation (`locksmith ca container-export`):**
  - Zero-touch export layouts for Docker Compose, Envoy SDS, and K3s.
  - Strict directory permissions enforcement (`0700` directories, `0600` private keys).
  - Double-buffered atomic write pattern (`os.Rename` with random temp nonces).
  - Background auto-rotation loop (`--renew`) refreshing certs at 50% TTL.
  - In-memory key zeroization on export completion.
- **Sovereign SPIFFE Workload API Daemon (`locksmith ca serve-spiffe`):**
  - Zero-dependency Unix Domain Socket listener serving `/v1/health`, `/v1/bundle`, and `/v1/svid`.
  - Kernel-level peer credential attestation (`LOCAL_PEERCRED`/`LOCAL_PEERPID` on macOS, `SO_PEERCRED` on Linux).
  - Kernel process start-timestamp verification (`sysctl KERN_PROC_PID` / `/proc/<pid>/stat`) preventing PID recycling attacks.
  - Local authorization policy engine (`policy.json`) with UID allowlists and trust domain enforcement.
  - Per-UID token bucket rate limiting.
- **Ecosystem Interlock & MicroVM Support:**
  - Vsock bridge listener (`--vsock-port`) enabling Aegisbox microVMs to securely consume SPIFFE identities from the host biometric enclave.
  - MicroVM CID attestation and automatic URI derivation (`spiffe://<trust-domain>/vm/cid/<cid>`).
  - Integration with `shield` reverse proxy SPIFFE client certificate URI SAN access control lists.
  - In-guest `aegisbox-spiffe-agent` workload proxy shim.

### Changed
- Refactored `pkg/ca` and `pkg/spiffe` to ensure all production and test functions maintain cyclomatic complexity <= 15.

---

## [3.1.2] - 2026-11-01

### Added
- Sovereign Dual-Root CA implementation (ECDSA P-256 + ML-DSA-65).
- Post-Quantum Cryptography (PQC) root generation and verification.
