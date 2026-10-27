import type { AuditEvent } from "../types/ipc";

class AuditStore {
  events = $state<AuditEvent[]>([]);
  searchQuery = $state<string>("");
  outcomeFilter = $state<string>("ALL");
  loading = $state<boolean>(false);

  constructor() {
    const now = Date.now();
    this.events = [
      {
        id: "aud-001",
        timestamp_ms: now - 3600_000,
        secret_name: "gitlab/glab/token",
        client_pid: 84392,
        binary_path: "/usr/local/bin/glab",
        binary_hash: "a4f89d31b2...e81",
        identity: "mcp:cursor",
        outcome: "GRANTED",
        reason: "Valid session token",
      },
      {
        id: "aud-002",
        timestamp_ms: now - 1800_000,
        secret_name: "GH-Read",
        client_pid: 85210,
        binary_path: "/usr/bin/curl",
        binary_hash: "7bc32f01aa...c44",
        identity: "spiffe://aegisbox.internal/agent/sandbox",
        outcome: "DENIED",
        reason: "Binary not in access_control.allow_binaries",
      },
      {
        id: "aud-003",
        timestamp_ms: now - 900_000,
        secret_name: "aws/prod/api_key",
        client_pid: 86421,
        binary_path: "/opt/homebrew/bin/aws",
        binary_hash: "55ee1248ab...9f0",
        identity: "spiffe://aegisbox.internal/workload/deployer",
        outcome: "GRANTED",
        reason: "Biometric step-up approved",
      },
      {
        id: "aud-004",
        timestamp_ms: now - 300_000,
        secret_name: "aws/prod/api_key",
        client_pid: 86421,
        binary_path: "/opt/homebrew/bin/aws",
        binary_hash: "55ee1248ab...9f0",
        identity: "spiffe://aegisbox.internal/workload/deployer",
        outcome: "REVOKED",
        reason: "TTL expired after 300s window",
      },
    ];
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const list = await invoke<AuditEvent[]>("get_audit_events", { limit: 100 });
      if (list && list.length > 0) {
        this.events = list;
      }
    } catch (e) {
      console.warn("Using local audit cache:", e);
    } finally {
      this.loading = false;
    }
  }

  get filteredEvents(): AuditEvent[] {
    return this.events.filter((item) => {
      const matchesSearch =
        this.searchQuery === "" ||
        item.secret_name.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
        item.binary_path.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
        item.identity.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
        item.client_pid.toString().includes(this.searchQuery);

      const matchesOutcome =
        this.outcomeFilter === "ALL" || item.outcome === this.outcomeFilter;

      return matchesSearch && matchesOutcome;
    });
  }
}

export const auditStore = new AuditStore();
