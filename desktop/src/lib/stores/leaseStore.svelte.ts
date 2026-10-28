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
  isRestarting = $state<boolean>(false);
  error = $state<string | null>(null);

  constructor() {
    this.leases = [];
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
      this.leases = Array.isArray(active) ? active : [];
      this.error = null;
    } catch (e: any) {
      this.error = e?.toString() || "Daemon offline";
      this.daemonStatus = {
        ...this.daemonStatus,
        online: false,
      };
    } finally {
      this.loading = false;
    }
  }

  async restartDaemon(): Promise<boolean> {
    this.isRestarting = true;
    this.error = null;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const status = await invoke<DaemonStatus>("restart_daemon");
      if (status) {
        this.daemonStatus = status;
      }
      await this.refresh();
      return true;
    } catch (e: any) {
      this.error = e?.toString() || "Failed to restart daemon";
      return false;
    } finally {
      this.isRestarting = false;
    }
  }

  async revoke(leaseId: string) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("revoke_active_lease", { leaseId });
      await this.refresh();
    } catch (e: any) {
      this.error = e?.toString() || "Failed to revoke lease";
      this.leases = this.leases.map((l) =>
        l.lease_id === leaseId ? { ...l, revoked: true } : l
      );
    }
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
      this.error = e?.toString() || `Failed to request lease for '${secretName}'`;
    }
  }
}

export const leaseStore = new LeaseStore();
