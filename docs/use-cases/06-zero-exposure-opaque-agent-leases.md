# Use Case 06: Zero-Exposure Opaque Agent Leases (`UB-MCP-v1`)

> **Goal:** Let autonomous AI coding agents run local integration tests against real APIs or databases **without ever exposing a single raw secret byte into the LLM's context window**.

## Why Raw `get_secret` Is Dangerous for Autonomous Agents
If an MCP server returns a plaintext API key directly to an LLM, that credential enters the model prompt history, tool-call logs, and potential prompt-injection exfiltration paths. Under `UB-MCP-v1`, `locksmith_get_secret` is **disabled by default** in `locksmith mcp` (failing closed with `LOCKSMITH_RAW_SECRET_BLOCKED`, `exit_code: 40`).

## The Opaque Lease Workflow
1. **Start an amortized local session (1 Touch ID prompt):**
   ```bash
   eval "$(fabrial session begin)"
   ```
2. **Agent checks out an opaque lease via MCP (`locksmith_checkout_lease`):**
   ```json
   {
     "secret_name": "STRIPE_TEST_KEY",
     "target_env_var": "STRIPE_API_KEY",
     "ttl_seconds": 120,
     "session_id": "sess_01JDX9J00..."
   }
   ```
   Locksmith returns **only** an opaque handle—never secret material:
   ```json
   {
     "lease_id": "lease_9f8a7b6c...",
     "env_var": "STRIPE_API_KEY",
     "expires_at": "2026-11-22T12:24:00Z",
     "delivery": "fd3_memory_slice"
   }
   ```
3. **Agent passes `lease_id` to `airlock_exec` or `aegisbox_exec`:**
   The sandbox redeems the single-use lease directly over `~/.locksmith/locksmith.sock` (`redeem_opaque_lease`, bound to `session_id` and peer UID), zeroes memory on exit (`clear` / `ExplicitBzero`), and fails closed (`exit_code: 40`) if the child attempts to echo the secret to stdout/stderr.
4. **Opt-in override (human-only debugging):**
   Only pass `locksmith mcp --allow-raw-agent-secrets` when explicitly debugging outside autonomous agent loops.
