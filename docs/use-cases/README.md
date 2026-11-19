# 💡 Locksmith End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/locksmith`](https://github.com/bonjoski/locksmith)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Locksmith** is a sovereign biometric hardware secrets vault and Model Context Protocol (MCP) provider for macOS (Touch ID / Secure Enclave) and Windows (Windows Hello / TPM). It provides zero-plaintext-on-disk secret management, in-memory fragmented slicing, ephemeral credential leases, and local SPIFFE X.509 certificate authority capabilities.

This directory provides task-oriented recipes solving common secret management and developer experience challenges.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Platform Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Biometric Touch ID Secrets Checkout](01-touch-id-secret-checkout.md)** | Retrieve sensitive API keys and tokens requiring Touch ID verification, with immediate memory scrubbing. | `locksmith get <secret>` | Secure Enclave / Touch ID |
| **[02. Zero-Plaintext MCP Secret Injection](02-mcp-secret-injection.md)** | Serve credentials directly to Claude Code / Cursor over local MCP JSON-RPC with automatic TTL expiration—no cleartext `.env` on disk. | `locksmith agent`<br/>`locksmith-mcp` | MCP Protocol / In-Memory Slicing |
| **[03. Ephemeral Subshell Environment Injection](03-ephemeral-subshell-injection.md)** | Spawn an interactive terminal or subshell with secrets injected into RAM for 300 seconds, automatically scrubbed on exit. | `locksmith env --ttl 300s -- bash` | RAM Environment Injection |
| **[04. Sovereign Local SPIFFE CA Issuance](04-spiffe-svid-issuance.md)** | Issue short-lived, cryptographically signed X.509 SVID certificates to authenticate local microVMs and workloads. | `locksmith ca issue --spiffe-id <id>` | SPIFFE Workload API |
| **[05. Automated Plaintext `.env` Migration](05-migrate-plaintext-env.md)** | Scan projects for hardcoded plaintext `.env` files and migrate them into the biometric keychain with one command. | `locksmith doctor --migrate` | Enclave Migration Tool |
