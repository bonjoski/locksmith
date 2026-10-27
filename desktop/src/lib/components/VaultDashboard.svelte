<script lang="ts">
  import { vaultStore } from "../stores/vaultStore.svelte";
  import { rotationStore } from "../stores/rotationStore.svelte";
  import StatusBadge from "./StatusBadge.svelte";
  import type { SecretItem } from "../types/ipc";

  let searchQuery = $state("");
  let biometricPromptKey = $state<string | null>(null);
  let biometricValue = $state<string | null>(null);
  let biometricError = $state<string | null>(null);

  let validCount = $derived(
    vaultStore.secrets.filter((s) => s.status === "StatusValid").length
  );
  let expiringCount = $derived(
    vaultStore.secrets.filter((s) => s.status === "StatusExpiring").length
  );
  let expiredCount = $derived(
    vaultStore.secrets.filter((s) => s.status === "StatusExpired").length
  );

  let filteredSecrets = $derived(
    vaultStore.secrets.filter(
      (s) =>
        searchQuery === "" ||
        s.key.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.owner_application.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.secret_type.toLowerCase().includes(searchQuery.toLowerCase())
    )
  );

  async function handleReveal(key: string) {
    biometricPromptKey = key;
    biometricValue = null;
    biometricError = null;
    const res = await vaultStore.revealBiometric(key);
    if (res) {
      biometricValue = res;
    } else {
      biometricError = "Biometric challenge failed or cancelled.";
    }
  }

  function closeBiometricModal() {
    biometricPromptKey = null;
    biometricValue = null;
    biometricError = null;
  }

  async function handleQuickRotate(secretName: string) {
    await rotationStore.triggerRotate(secretName);
    await vaultStore.refresh();
  }
</script>

<div class="space-y-4">
  <!-- Expiration Radar Metrics -->
  <div class="grid grid-cols-4 gap-3">
    <!-- Total -->
    <div class="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
      <div class="text-[11px] font-mono text-zinc-400">Total Credentials</div>
      <div class="text-xl font-bold text-zinc-100 mt-1">{vaultStore.secrets.length}</div>
      <div class="text-[10px] text-zinc-500 mt-0.5">Biometrically bound in Secure Enclave</div>
    </div>

    <!-- Valid -->
    <div class="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
      <div class="text-[11px] font-mono text-emerald-400">Status Valid</div>
      <div class="text-xl font-bold text-emerald-400 mt-1">{validCount}</div>
      <div class="text-[10px] text-zinc-500 mt-0.5">Healthy & rotated within window</div>
    </div>

    <!-- Expiring Soon -->
    <div class="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
      <div class="text-[11px] font-mono text-amber-400">Expiring Soon</div>
      <div class="text-xl font-bold text-amber-400 mt-1">{expiringCount}</div>
      <div class="text-[10px] text-zinc-500 mt-0.5">Requires auto-refresh or renewal</div>
    </div>

    <!-- Expired -->
    <div class="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
      <div class="text-[11px] font-mono text-rose-400">Status Expired</div>
      <div class="text-xl font-bold text-rose-400 mt-1">{expiredCount}</div>
      <div class="text-[10px] text-zinc-500 mt-0.5">Blocked from ephemeral lease issue</div>
    </div>
  </div>

  <!-- Table Controls -->
  <div class="flex items-center justify-between">
    <div>
      <h3 class="text-sm font-semibold tracking-tight text-zinc-200">
        Credential Inventory & Expiration Radar
      </h3>
    </div>

    <div class="flex items-center space-x-2">
      <input
        type="text"
        placeholder="Search credentials..."
        bind:value={searchQuery}
        class="bg-zinc-900 border border-zinc-700/80 rounded-md px-2.5 py-1 text-xs text-zinc-200 placeholder-zinc-500 font-sans focus:outline-none focus:border-cyan-500 w-44"
      />

      <button
        onclick={() => vaultStore.refresh()}
        class="text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 px-2.5 py-1.5 rounded-md transition-colors"
        title="Refresh Vault"
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      </button>
    </div>
  </div>

  <!-- Secrets Table -->
  <div class="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-900/30 backdrop-blur-sm">
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="bg-zinc-900/70 border-b border-zinc-800 text-zinc-400 font-mono">
          <tr>
            <th class="py-2.5 px-3 font-medium">Secret Key</th>
            <th class="py-2.5 px-3 font-medium">Radar Status</th>
            <th class="py-2.5 px-3 font-medium">Type</th>
            <th class="py-2.5 px-3 font-medium">Application</th>
            <th class="py-2.5 px-3 font-medium">Expiration Window</th>
            <th class="py-2.5 px-3 font-medium text-right">Biometric Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-800/60 font-sans">
          {#each filteredSecrets as secret (secret.key)}
            <tr class="hover:bg-zinc-800/30 transition-colors">
              <!-- Key -->
              <td class="py-2.5 px-3 font-mono font-medium text-zinc-100">
                <div class="flex items-center space-x-1.5">
                  <span class="text-cyan-400">🔑</span>
                  <span>{secret.key}</span>
                </div>
              </td>

              <!-- Status -->
              <td class="py-2.5 px-3">
                <StatusBadge status={secret.status} />
              </td>

              <!-- Type -->
              <td class="py-2.5 px-3 font-mono text-zinc-300">
                <span class="bg-zinc-800/70 px-1.5 py-0.5 rounded text-[11px] border border-zinc-700/50">
                  {secret.secret_type || 'generic'}
                </span>
              </td>

              <!-- Owner Application -->
              <td class="py-2.5 px-3 text-zinc-300">
                {secret.owner_application || '—'}
              </td>

              <!-- Expiration Window -->
              <td class="py-2.5 px-3 font-mono text-zinc-400 text-[11px]">
                {secret.expires_at ? secret.expires_at.replace("T", " ").replace("Z", "") : "Never"}
              </td>

              <!-- Actions -->
              <td class="py-2.5 px-3 text-right">
                <div class="flex items-center justify-end space-x-1.5">
                  <button
                    onclick={() => handleReveal(secret.key)}
                    class="text-xs bg-cyan-600/10 hover:bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded transition-colors font-medium flex items-center space-x-1"
                    title="Touch ID Step-Up Challenge"
                  >
                    <span>Touch ID Reveal</span>
                  </button>

                  <button
                    onclick={() => handleQuickRotate(secret.key)}
                    class="text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2 py-0.5 rounded transition-colors font-medium"
                    title="Rotate now"
                  >
                    Rotate
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Biometric Reveal Modal -->
{#if biometricPromptKey}
  <div class="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
    <div class="bg-zinc-900 border border-zinc-700 rounded-2xl max-w-sm w-full p-6 text-center space-y-4 shadow-2xl">
      <!-- Touch ID Icon -->
      <div class="mx-auto w-14 h-14 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
        <svg class="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 004.07 8.163M8 11a4 4 0 018 0" />
        </svg>
      </div>

      <div class="space-y-1">
        <h4 class="text-base font-semibold text-zinc-100">Biometric Step-Up</h4>
        <p class="text-xs text-zinc-400">
          Hardware authentication required to reveal <span class="font-mono text-zinc-200 font-semibold">{biometricPromptKey}</span>
        </p>
      </div>

      {#if biometricValue}
        <div class="bg-zinc-950 border border-emerald-500/40 rounded-lg p-3 text-left space-y-1">
          <div class="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">Secret Decrypted (Memory Protected)</div>
          <div class="font-mono text-xs text-zinc-100 break-all select-all font-semibold">
            {biometricValue}
          </div>
        </div>
      {:else if biometricError}
        <div class="bg-rose-950/40 border border-rose-500/40 rounded-lg p-2.5 text-xs text-rose-300">
          {biometricError}
        </div>
      {:else}
        <div class="py-2 text-xs font-mono text-cyan-400 animate-pulse">
          Touch ID / Apple Watch challenge pending...
        </div>
      {/if}

      <div class="pt-2">
        <button
          onclick={closeBiometricModal}
          class="w-full py-1.5 text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg transition-colors"
        >
          Close Secret Reveal
        </button>
      </div>
    </div>
  </div>
{/if}
