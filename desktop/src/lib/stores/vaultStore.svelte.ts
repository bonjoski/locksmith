import type { SecretItem } from "../types/ipc";

class VaultStore {
  secrets = $state<SecretItem[]>([]);
  loading = $state<boolean>(false);
  revealedSecrets = $state<Record<string, string>>({});
  revealingKey = $state<string | null>(null);

  constructor() {
    this.secrets = [];
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const list = await invoke<SecretItem[]>("get_vault_secrets");
      this.secrets = Array.isArray(list) ? list : [];
    } catch (e) {
      console.warn("Error refreshing vault secrets:", e);
    } finally {
      this.loading = false;
    }
  }

  async revealBiometric(key: string): Promise<string | null> {
    this.revealingKey = key;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const res = await invoke<{ success: boolean; value?: string; error?: string }>(
        "reveal_secret_biometric",
        { key }
      );
      if (res.success && res.value) {
        this.revealedSecrets = {
          ...this.revealedSecrets,
          [key]: res.value,
        };
        return res.value;
      }
      return null;
    } catch (e) {
      console.warn("Biometric reveal failed:", e);
      return null;
    } finally {
      this.revealingKey = null;
    }
  }

  hideSecret(key: string) {
    const copy = { ...this.revealedSecrets };
    delete copy[key];
    this.revealedSecrets = copy;
  }

  async deleteSecret(key: string) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("delete_vault_secret", { key });
    } catch (e) {
      console.warn("Delete secret error:", e);
    }
    this.secrets = this.secrets.filter((s) => s.key !== key);
  }
}

export const vaultStore = new VaultStore();
