import type { AuditEvent } from "../types/ipc";

class AuditStore {
  events = $state<AuditEvent[]>([]);
  searchQuery = $state<string>("");
  outcomeFilter = $state<string>("ALL");
  loading = $state<boolean>(false);

  constructor() {
    this.events = [];
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const list = await invoke<AuditEvent[]>("get_audit_events", { limit: 100 });
      this.events = Array.isArray(list) ? list : [];
    } catch (e) {
      console.warn("Error refreshing audit events:", e);
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
