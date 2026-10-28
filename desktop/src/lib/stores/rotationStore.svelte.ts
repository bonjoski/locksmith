import type { AccessControlItem, RotationRuleItem } from "../types/ipc";

class RotationStore {
  rules = $state<RotationRuleItem[]>([]);
  accessControl = $state<AccessControlItem>({
    allow_binaries: [],
    deny_binaries: [],
  });
  rotatingSecret = $state<string | null>(null);
  rotationMessage = $state<string | null>(null);
  loading = $state<boolean>(false);

  constructor() {
    this.rules = [];
    this.accessControl = {
      allow_binaries: [],
      deny_binaries: [],
    };
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const rules = await invoke<RotationRuleItem[]>("get_rotation_rules");
      this.rules = Array.isArray(rules) ? rules : [];

      const ac = await invoke<AccessControlItem>("get_access_control");
      if (ac) {
        this.accessControl = ac;
      }
    } catch (e) {
      console.warn("Error refreshing rotation config:", e);
    } finally {
      this.loading = false;
    }
  }

  async triggerRotate(secretName: string) {
    this.rotatingSecret = secretName;
    this.rotationMessage = null;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const res = await invoke<{ success: boolean; message: string }>(
        "trigger_secret_rotation",
        { secretName }
      );
      this.rotationMessage = res.message;
    } catch (e: any) {
      this.rotationMessage = `Rotation failed for '${secretName}': ${e?.message || e?.toString() || e}`;
    } finally {
      this.rotatingSecret = null;
    }
  }

  async addAllowBinary(path: string) {
    if (!path || this.accessControl.allow_binaries.includes(path)) return;
    const updated = [...this.accessControl.allow_binaries, path];
    this.accessControl = {
      ...this.accessControl,
      allow_binaries: updated,
    };
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("update_access_control", {
        allow: this.accessControl.allow_binaries,
        deny: this.accessControl.deny_binaries,
      });
    } catch (e) {
      console.warn("Update access control error:", e);
    }
  }

  async removeAllowBinary(path: string) {
    const updated = this.accessControl.allow_binaries.filter((p) => p !== path);
    this.accessControl = {
      ...this.accessControl,
      allow_binaries: updated,
    };
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("update_access_control", {
        allow: this.accessControl.allow_binaries,
        deny: this.accessControl.deny_binaries,
      });
    } catch (e) {
      console.warn("Update access control error:", e);
    }
  }
}

export const rotationStore = new RotationStore();
