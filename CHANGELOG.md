# Changelog

All notable changes to `locksmith` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.2.4] - 2026-11-05

### Security & Hardening (GHSA-wfmr-rw42-3rv7 Gap Closure)
- **RFC 5280 Supernet `/0` CIDR Bypass Closure:**
  - Tightened `isPrivateOrLoopbackIPNet` to validate mask width (IPv4 $\ge 8$, IPv6 $\ge 7$) and calculate both base IP and broadcast/last IP against loopback and RFC 1918 private IP ranges.
  - Explicitly rejects supernet masks (`127.0.0.0/0`, `::/0`) and multicast spaces (`224.0.0.0/4`).
- **Dotless TLD & Broad Domain Name Constraints Hardening:**
  - Default Root CA `PermittedDNSDomains` tightened strictly to `localhost` and `.localhost` (removing `.local` and `.internal` from defaults).
  - Implemented `isSovereignDomain` and `validateRootDNSDomains`, rejecting dotless TLD subtree constraints (`com`, `net`) and unreserved pseudo-TLDs (`.lan`).
  - Added strict fail-closed enforcement in `ca init` requiring `--allow-broad-domains` when configuring broad sovereign domains (`.local`, `.internal`, `.home.arpa`).
- **RFC 5280 URI Name Constraints Alignment & Public gTLD Elimination:**
  - Removed Google public gTLD `local.dev` from default URI name constraints.
  - Implemented `validateRootURIDomains` stripping URI schemes per RFC 5280 Section 4.2.1.10 and validating hostnames against sovereign constraints.
- **Dynamic MicroVM Provisioning & Multi-Agent Atomic I/O:**
  - Added `locksmith ca derive-bridge-token --cid <uint32> [--key-file <path>] [--ca-dir <path>]` command for out-of-band token generation.
  - Implemented atomic file write utility `writeKeyFileAtomic` with sync and rename semantics, preventing truncation races under parallel subagents.
  - Added `--no-persist-bridge-key` flag and marked `--bridge-token` deprecated with guidance to use `--bridge-token-file` or `LOCKSMITH_BRIDGE_TOKEN` to avoid ps argument leaks.
  - Enforced 32-byte key minimum in `NewBridgeTokenDeriver` and `resolveBridgeCredentials`.
- **Policy Diagnostics & Parser Hardening:**
  - Surfaced `pol.Warnings()` during SPIFFE Workload daemon startup.
  - Refactored `parsePermittedIPs` to fail closed on invalid IP strings and normalize IPv4 to 4-byte representations.
  - Extended `parseVsockAddr` to support angle-bracketed and URI-prefixed vsock peer address formats.

## [3.2.3] - 2026-11-04

### Security & Hardening (GHSA-wfmr-rw42-3rv7 Residual Mitigations)
- **Multi-VM SPIFFE Bridge CID Transposition Defense:**
  - Implemented `BridgeTokenDeriver` generating domain-separated cryptographic bridge tokens per microVM CID: `HMAC-SHA256(K_bridge, "locksmith-spiffe-bridge-v1:cid:" || CID)`.
  - Added strict constant-time token verification via `crypto/subtle.ConstantTimeCompare`, blocking cross-CID transposition attacks where a compromised microVM attempts to impersonate another CID.
- **Hardened Bridge Token & Key Management:**
  - Added `--bridge-token-file`, `--bridge-key-file`, and `LOCKSMITH_BRIDGE_TOKEN` environment variable support.
  - Replaced raw stdout printing of bridge tokens with mode `0600` disk persistence (`bridge.token`, `bridge.key`) and stderr fingerprint logging.
- **Dynamic vsock Peer CID Attestation:**
  - Implemented `parseVsockAddr` extracting peer CID directly from native `vsock` addresses, eliminating hardcoded fallback CIDs and failing closed if unidentifiable.
- **Configurable Sovereign Name Constraints:**
  - Added `GenerateRootCAWithConfig` supporting operator-defined `--permitted-dns`, `--permitted-ip`, and `--permitted-uri` flags in `locksmith ca init`.
  - Added `--allow-broad-domains` flag requiring explicit consent when initializing broader sovereign domain perimeters.
- **Disambiguated Policy Binary Provenance:**
  - Implemented explicit prefix grammar (`sha256:`, `path:`, `comm:`, or 64-hex SHA-256) in `matchesSingleBinary`.
  - Added `(p *Policy) Validate()` emitting warnings when unauthenticated binary path or comm strings are used without cryptographic hash digests.
- **Comprehensive Root CA Security Profile Validation:**
  - Added `validateRootSecurityProfile` checking `PermittedDNSDomainsCritical`, `MaxPathLenZero`, loopback/private IP ranges, and rejecting public internet TLDs prior to trust store installation.

## [3.2.2] - 2026-11-04

### Security & Hardening (GHSA-wfmr-rw42-3rv7)
- **Mandatory Enclave Sealing for Sovereign CA Root Keys:**
  - Hardware enclave storage (Apple Keychain / TPM) is now enforced during `locksmith ca init`. Platform enclave failure is fatal by default to prevent silent plaintext disk leakage.
  - Plaintext disk private keys (`root-ca.key`, `root-ca-pqc.key`) are purged on successful keychain import and never written to disk without `--allow-unsealed-disk-keys`.
  - Prominent stderr warnings on `loadRootCA()` if private keys are loaded from unsealed disk storage.
- **RFC 5280 Critical Name Constraints Enforcement:**
  - Root CAs (ECDSA P-256 and PQC ML-DSA-65) now enforce `critical` `NameConstraints`:
    - DNS: `localhost`, `.localhost`, `local`, `.local`, `internal`, `.internal`
    - IP Ranges: `127.0.0.0/8`, `::1/128`
    - URI Domains: `bonjoski.local`, `local.dev`
  - Strict pre-issuance validation in `IssueServerCert` and `IssuePQCServerCert` returns `ErrForbiddenHostname` for public domains or external IPs.
  - SVID issuance verifies trust domain URI against CA permitted URI domains.
  - `locksmith ca trust` guards the system trust store, rejecting unconstrained root CAs without `--force-unconstrained`.
- **SPIFFE Loopback TCP Bridge Attestation & MicroVM Pinned Lineage:**
  - Eliminated unattested `VsockCID: 3` synthesis over loopback TCP connections.
  - Loopback TCP bridge requests require pre-shared `X-Locksmith-Bridge-Token` authentication (`--bridge-token`).
  - Empty `AllowedCIDs` fails closed by default.
  - MicroVM SVID derivation is strictly pinned to `spiffe://<td/vm/cid/<cid>` unless authorized by an explicit rule.
- **SPIFFE Policy Rule Engine:**
  - Authorizes caller identities against glob patterns, UID constraints, CID constraints, and binary provenance (SHA-256 hash digests, absolute executable paths, and process comm names).
- **Concurrency & Memory Safety:**
  - Fixed concurrent data race in `AuthZeroizeHook` (`pkg/slice/slice.go`) with read-write mutex synchronization.

## [3.2.1] - 2026-11-03

### Added
- **Core Zero-Trust Audit Logging Pipeline (`pkg/audit`):**
  - Thread-safe, cross-process advisory locked atomic JSONL logger writing to `~/.locksmith/audit.jsonl`.
  - Automatic attribution capturing verified caller PID, binary executable path, executable SHA-256 digest, and contextual workload identity.
  - Strict zero-knowledge invariant: secret values, passwords, and private tokens are never written to disk or audit reasons.
- **Access Point Instrumentation:**
  - Vault retrievals, auto-rotations, and denials in `pkg/locksmith/locksmith.go`.
  - Git credential helper queries (`identity: "git-credential"`).
  - GPG Pinentry passphrase lookups (`identity: "gpg:pinentry"`).
  - CLI commands (`get`, `run`, `slice`), Summon provider (`summon`), and MCP server (`mcp:tools`).
  - ETX lease checkouts, client revocations, and TTL/process liveness death events in `pkg/locksmith/lease_manager.go`.
- **Mandatory Audit Contract & Adversarial Test Coverage:**
  - `pkg/locksmith/adversarial_audit_test.go`:
    - `ADV-AUDIT-01`: Zero-knowledge payload leak prevention across high-entropy API keys and RSA/EC private keys.
    - `ADV-AUDIT-02`: Non-repudiation enforcement proving every vault lookup produces an immutable audit record.
    - `ADV-AUDIT-03`: PID and binary impersonation defense ensuring socket peer credentials cannot be forged by untrusted payloads.
    - `ADV-AUDIT-04`: High-throughput concurrent race and line corruption stress tests.
  - `pkg/locksmith/audit_integration_test.go`: End-to-end integration tests for `Get`, `LeaseManager`, and process liveness expiration.
  - Contract assertions in `cmd/locksmith/cmd/credential_cmd_test.go` and `pkg/agent/agent_test.go`.

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
