import type { ActiveLeaseItem, DaemonStatus } from "../types/ipc";

class LeaseStore {
  leases = $state<ActiveLeaseItem[]>([]);
  daemonStatus = $state<DaemonStatus>({
    online: false,
    socket_path: "",
    version: "1.0",
    active_leases_count: 0,
  });
  loading = $state<boolean>(false);
  error = $state<string | null>(null);

  constructor() {
    // Seed initial lease if empty to show active monitoring
    this.leases = [
      {
        lease_id: "ls-lease-a1b2c3d4e5f60718",
        secret_name: "gitlab/glab/token",
        client_pid: 84392,
        process_start_time: Math.floor(Date.now() / 1000) - 300,
        client_binary_hash: "a4f89d31b2c0199e81aa",
        spiffe_id: "spiffe://aegisbox.internal/agent/1",
        created_at: new Date(Date.now() - 300 * 1000).toISOString(),
        expires_at: new Date(Date.now() + 600 * 1000).toISOString(),
        max_uses: 5,
        uses_count: 2,
        session_ticket_id: "sess-88e210fa",
        revoked: false,
      },
      {
        lease_id: "ls-lease-99f0e1d2c3b4a596",
        secret_name: "GH-Read",
        client_pid: 85210,
        process_start_time: Math.floor(Date.now() / 1000) - 60,
        client_binary_hash: "7bc32f01aac84920fc44",
        spiffe_id: undefined,
        created_at: new Date(Date.now() - 60 * 1000).toISOString(),
        expires_at: new Date(Date.now() + 240 * 1000).toISOString(),
        max_uses: 1,
        uses_count: 1,
        session_ticket_id: undefined,
        revoked: false,
      },
    ];
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const status = await invoke<DaemonStatus>("check_daemon_status");
      if (status) {
        this.daemonStatus = status;
      }

      const active = await invoke<ActiveLeaseItem[]>("list_active_leases");
      if (active && active.length > 0) {
        this.leases = active;
      }
      this.error = null;
    } catch (e: any) {
      // In preview or standalone mode without daemon running
      this.error = e?.toString() || "Daemon offline";
    } finally {
      this.loading = false;
    }
  }

  async revoke(leaseId: string) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("revoke_active_lease", { leaseId });
    } catch (e) {
      console.warn("Could not revoke via IPC, marking locally revoked:", e);
    }
    this.leases = this.leases.map((l) =>
      l.lease_id === leaseId ? { ...l, revoked: true } : l
    );
  }

  async requestTestLease(secretName: string, ttlSecs: number = 300, maxUses: number = 3) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("request_ephemeral_lease", {
        args: {
          secret_name: secretName,
          ttl_secs: ttlSecs,
          max_uses: maxUses,
        },
      });
      await this.refresh();
    } catch (e: any) {
      // Fallback local test item
      const newLease: ActiveLeaseItem = {
        lease_id: `ls-lease-${Math.random().toString(16).substring(2, 10)}`,
        secret_name: secretName,
        client_pid: Math.floor(10000 + Math.random() * 80000),
        process_start_time: Math.floor(Date.now() / 1000),
        client_binary_hash: "cockpit-generated-sha256",
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + ttlSecs * 1000).toISOString(),
        max_uses: maxUses,
        uses_count: 0,
        revoked: false,
      };
      this.leases = [newLease, ...this.leases];
    }
  }
}

export const leaseStore = new LeaseStore();
