import type { SecretItem } from "../types/ipc";

class VaultStore {
  secrets = $state<SecretItem[]>([]);
  loading = $state<boolean>(false);
  revealedSecrets = $state<Record<string, string>>({});
  revealingKey = $state<string | null>(null);

  constructor() {
    this.secrets = [
      {
        key: "gitlab/glab/token",
        secret_type: "oauth_token",
        owner_application: "gitlab",
        source_url: "https://gitlab.com/oauth/token",
        created_at: new Date(Date.now() - 3600 * 1000).toISOString(),
        expires_at: new Date(Date.now() + 1800 * 1000).toISOString(),
        status: "StatusExpiring",
        metadata: {
          gitlab_refresh_token: "locksmith://gitlab/glab/oauth2_refresh_token",
        },
      },
      {
        key: "GH-Read",
        secret_type: "token",
        owner_application: "github",
        source_url: "https://api.github.com",
        created_at: new Date(Date.now() - 7200 * 1000).toISOString(),
        expires_at: new Date(Date.now() + 86400 * 1000).toISOString(),
        status: "StatusValid",
        metadata: {
          github_app_client_id: "locksmith://github/app/clientid",
        },
      },
      {
        key: "gh-test",
        secret_type: "token",
        owner_application: "github",
        source_url: "https://api.github.com",
        created_at: new Date(Date.now() - 14400 * 1000).toISOString(),
        expires_at: new Date(Date.now() + 43200 * 1000).toISOString(),
        status: "StatusValid",
        metadata: {},
      },
      {
        key: "aws/prod/api_key",
        secret_type: "api_key",
        owner_application: "aws",
        source_url: "https://aws.amazon.com",
        created_at: new Date(Date.now() - 86400 * 35 * 1000).toISOString(),
        expires_at: new Date(Date.now() - 86400 * 5 * 1000).toISOString(),
        status: "StatusExpired",
        metadata: {},
      },
    ];
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const list = await invoke<SecretItem[]>("get_vault_secrets");
      if (list && list.length > 0) {
        this.secrets = list;
      }
    } catch (e) {
      console.warn("Using local vault cache:", e);
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
      // Local step-up fallback simulation
      const val = `mock-revealed-${key.replace('/', '_')}-bio-pass`;
      this.revealedSecrets = {
        ...this.revealedSecrets,
        [key]: val,
      };
      return val;
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
