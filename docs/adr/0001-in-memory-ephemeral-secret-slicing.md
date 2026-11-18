# ADR-0001: In-Memory Ephemeral Secret Slicing (`locksmith slice`)

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/slice`, `cmd/locksmith/cmd/slice.go`
- **Deciders:** Lead Security Architect & Cryptographic Systems Engineer

---

## 1. Context & Problem Statement

Developer tools and AI agents typically inject secrets into child processes via environment variables (e.g. `export GITHUB_TOKEN=...`).
- Environment variables are exposed globally to all child processes spawned by the parent shell.
- Any process on Linux/macOS with matching UID can read `/proc/<pid>/environ` or query `ps eww <pid>`.
- Core dumps, crash reports, and process listings leak static credentials to disk and logging pipelines.

---

## 2. Decision Outcome

We introduced **In-Memory Ephemeral Secret Slicing (`locksmith slice`)**:

1. **Anonymous Memory Descriptors (`memfd_create` / `mach_vm_allocate`):**
   - Secrets are written to anonymous memory-backed file descriptors (`FD=3`) that have no corresponding filesystem path.
2. **Instant Memory Zeroization:**
   - As soon as the child process completes its initial handshake or reads the payload, the memory buffer is explicitly zeroized using memory fences (`subtle.ConstantTimeCopy` / `memset_s`).
3. **Process-Level Cloaking:**
   - Secrets never enter the environment block or command-line arguments, remaining completely invisible in `ps` and `/proc/<pid>/environ`.

---

## 3. Consequences

- **Positive:** Eliminates credential leakage via process tables, environment dumping, and core dumps; zero disk footprint.
- **Negative:** Child processes or integration shims must read from the designated file descriptor or anonymous pipe.
