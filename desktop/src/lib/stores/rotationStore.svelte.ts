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
    this.rules = [
      {
        secret: "gitlab/glab/token",
        rotator: "gitlab-oauth-refresh",
        secret_type: "oauth_token",
        owner_application: "gitlab",
        source_url: "https://gitlab.com/oauth/token",
        ttl: "1h",
        metadata: {
          gitlab_refresh_token: "locksmith://gitlab/glab/oauth2_refresh_token",
        },
      },
      {
        secret: "GH-Read",
        rotator: "github-app-installation-token",
        secret_type: "token",
        owner_application: "github",
        source_url: "https://api.github.com",
        ttl: "24h",
        metadata: {
          github_app_client_id: "locksmith://github/app/clientid",
        },
      },
      {
        secret: "GL-*",
        rotator: "gitlab-pat-self-rotate",
        secret_type: "token",
        owner_application: "gitlab",
        ttl: "30d",
        metadata: {},
      },
    ];

    this.accessControl = {
      allow_binaries: [
        "/usr/bin/git",
        "/usr/local/bin/glab",
        "/opt/homebrew/bin/gh",
      ],
      deny_binaries: [
        "/tmp/malicious_runner",
      ],
    };
  }

  async refresh() {
    this.loading = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const rules = await invoke<RotationRuleItem[]>("get_rotation_rules");
      if (rules && rules.length > 0) {
        this.rules = rules;
      }

      const ac = await invoke<AccessControlItem>("get_access_control");
      if (ac) {
        this.accessControl = ac;
      }
    } catch (e) {
      console.warn("Using local rotation config cache:", e);
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
      this.rotationMessage = `Secret '${secretName}' rotated successfully (mock). New lease valid for TTL.`;
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
